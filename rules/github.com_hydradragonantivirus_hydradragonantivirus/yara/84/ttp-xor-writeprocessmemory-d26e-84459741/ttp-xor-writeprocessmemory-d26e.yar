rule TTP_XOR_WriteProcessMemory_d26e {
  strings:
    $key_d26e = { 85 1c [2] b7 3e [2] b1 0b [2] 9f 0b [2] a0 17 }

  condition:
    any of them
}
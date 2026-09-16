rule TTP_XOR_WriteProcessMemory_c36e {
  strings:
    $key_c36e = { 94 1c [2] a6 3e [2] a0 0b [2] 8e 0b [2] b1 17 }

  condition:
    any of them
}
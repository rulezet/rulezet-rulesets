rule TTP_XOR_WriteProcessMemory_d22e {
  strings:
    $key_d22e = { 85 5c [2] b7 7e [2] b1 4b [2] 9f 4b [2] a0 57 }

  condition:
    any of them
}
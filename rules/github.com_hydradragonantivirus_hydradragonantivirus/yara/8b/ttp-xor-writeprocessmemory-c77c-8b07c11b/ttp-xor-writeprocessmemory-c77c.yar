rule TTP_XOR_WriteProcessMemory_c77c {
  strings:
    $key_c77c = { 90 0e [2] a2 2c [2] a4 19 [2] 8a 19 [2] b5 05 }

  condition:
    any of them
}
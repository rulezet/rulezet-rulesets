rule TTP_XOR_WriteProcessMemory_c47c {
  strings:
    $key_c47c = { 93 0e [2] a1 2c [2] a7 19 [2] 89 19 [2] b6 05 }

  condition:
    any of them
}
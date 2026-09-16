rule TTP_XOR_WriteProcessMemory_6242 {
  strings:
    $key_6242 = { 35 30 [2] 07 12 [2] 01 27 [2] 2f 27 [2] 10 3b }

  condition:
    any of them
}
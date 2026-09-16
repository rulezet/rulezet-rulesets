rule TTP_XOR_WriteProcessMemory_1022 {
  strings:
    $key_1022 = { 47 50 [2] 75 72 [2] 73 47 [2] 5d 47 [2] 62 5b }

  condition:
    any of them
}
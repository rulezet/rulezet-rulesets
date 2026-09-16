rule TTP_XOR_WriteProcessMemory_1277 {
  strings:
    $key_1277 = { 45 05 [2] 77 27 [2] 71 12 [2] 5f 12 [2] 60 0e }

  condition:
    any of them
}
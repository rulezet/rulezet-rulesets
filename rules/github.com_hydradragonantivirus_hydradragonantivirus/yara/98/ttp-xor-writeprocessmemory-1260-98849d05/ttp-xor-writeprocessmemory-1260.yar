rule TTP_XOR_WriteProcessMemory_1260 {
  strings:
    $key_1260 = { 45 12 [2] 77 30 [2] 71 05 [2] 5f 05 [2] 60 19 }

  condition:
    any of them
}
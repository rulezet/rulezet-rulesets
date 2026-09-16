rule TTP_XOR_WriteProcessMemory_1264 {
  strings:
    $key_1264 = { 45 16 [2] 77 34 [2] 71 01 [2] 5f 01 [2] 60 1d }

  condition:
    any of them
}
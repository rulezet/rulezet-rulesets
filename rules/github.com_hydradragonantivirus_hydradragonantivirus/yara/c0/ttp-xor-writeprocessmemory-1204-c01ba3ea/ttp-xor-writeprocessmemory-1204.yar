rule TTP_XOR_WriteProcessMemory_1204 {
  strings:
    $key_1204 = { 45 76 [2] 77 54 [2] 71 61 [2] 5f 61 [2] 60 7d }

  condition:
    any of them
}
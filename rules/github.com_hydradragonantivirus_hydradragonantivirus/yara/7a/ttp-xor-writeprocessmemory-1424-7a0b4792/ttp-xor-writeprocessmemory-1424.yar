rule TTP_XOR_WriteProcessMemory_1424 {
  strings:
    $key_1424 = { 43 56 [2] 71 74 [2] 77 41 [2] 59 41 [2] 66 5d }

  condition:
    any of them
}
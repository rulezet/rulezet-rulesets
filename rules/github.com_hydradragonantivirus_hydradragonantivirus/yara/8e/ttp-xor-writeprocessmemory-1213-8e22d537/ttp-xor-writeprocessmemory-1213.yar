rule TTP_XOR_WriteProcessMemory_1213 {
  strings:
    $key_1213 = { 45 61 [2] 77 43 [2] 71 76 [2] 5f 76 [2] 60 6a }

  condition:
    any of them
}
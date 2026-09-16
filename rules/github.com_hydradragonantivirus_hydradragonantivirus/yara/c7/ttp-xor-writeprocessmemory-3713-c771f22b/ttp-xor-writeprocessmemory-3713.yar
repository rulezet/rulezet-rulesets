rule TTP_XOR_WriteProcessMemory_3713 {
  strings:
    $key_3713 = { 60 61 [2] 52 43 [2] 54 76 [2] 7a 76 [2] 45 6a }

  condition:
    any of them
}
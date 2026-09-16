rule TTP_XOR_WriteProcessMemory_7703 {
  strings:
    $key_7703 = { 20 71 [2] 12 53 [2] 14 66 [2] 3a 66 [2] 05 7a }

  condition:
    any of them
}
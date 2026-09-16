rule TTP_XOR_WriteProcessMemory_2663 {
  strings:
    $key_2663 = { 71 11 [2] 43 33 [2] 45 06 [2] 6b 06 [2] 54 1a }

  condition:
    any of them
}
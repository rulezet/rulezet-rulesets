rule TTP_XOR_WriteProcessMemory_3703 {
  strings:
    $key_3703 = { 60 71 [2] 52 53 [2] 54 66 [2] 7a 66 [2] 45 7a }

  condition:
    any of them
}
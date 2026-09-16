rule TTP_XOR_WriteProcessMemory_3736 {
  strings:
    $key_3736 = { 60 44 [2] 52 66 [2] 54 53 [2] 7a 53 [2] 45 4f }

  condition:
    any of them
}
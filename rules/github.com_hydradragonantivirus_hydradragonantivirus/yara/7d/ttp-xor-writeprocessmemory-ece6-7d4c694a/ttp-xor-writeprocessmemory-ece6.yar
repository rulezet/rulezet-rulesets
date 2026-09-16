rule TTP_XOR_WriteProcessMemory_ece6 {
  strings:
    $key_ece6 = { bb 94 [2] 89 b6 [2] 8f 83 [2] a1 83 [2] 9e 9f }

  condition:
    any of them
}
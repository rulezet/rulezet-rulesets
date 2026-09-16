rule TTP_XOR_WriteProcessMemory_3ee6 {
  strings:
    $key_3ee6 = { 69 94 [2] 5b b6 [2] 5d 83 [2] 73 83 [2] 4c 9f }

  condition:
    any of them
}
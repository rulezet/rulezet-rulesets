rule TTP_XOR_WriteProcessMemory_3ee2 {
  strings:
    $key_3ee2 = { 69 90 [2] 5b b2 [2] 5d 87 [2] 73 87 [2] 4c 9b }

  condition:
    any of them
}
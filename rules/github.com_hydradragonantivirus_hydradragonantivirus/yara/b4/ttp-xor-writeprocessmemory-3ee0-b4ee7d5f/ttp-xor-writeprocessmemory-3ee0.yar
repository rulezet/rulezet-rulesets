rule TTP_XOR_WriteProcessMemory_3ee0 {
  strings:
    $key_3ee0 = { 69 92 [2] 5b b0 [2] 5d 85 [2] 73 85 [2] 4c 99 }

  condition:
    any of them
}
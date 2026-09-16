rule TTP_XOR_WriteProcessMemory_e733 {
  strings:
    $key_e733 = { b0 41 [2] 82 63 [2] 84 56 [2] aa 56 [2] 95 4a }

  condition:
    any of them
}
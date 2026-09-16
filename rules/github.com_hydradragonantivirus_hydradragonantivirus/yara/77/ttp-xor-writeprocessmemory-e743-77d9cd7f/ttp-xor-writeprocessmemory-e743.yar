rule TTP_XOR_WriteProcessMemory_e743 {
  strings:
    $key_e743 = { b0 31 [2] 82 13 [2] 84 26 [2] aa 26 [2] 95 3a }

  condition:
    any of them
}
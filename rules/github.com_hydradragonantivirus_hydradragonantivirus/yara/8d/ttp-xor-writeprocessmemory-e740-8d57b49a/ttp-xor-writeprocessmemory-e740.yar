rule TTP_XOR_WriteProcessMemory_e740 {
  strings:
    $key_e740 = { b0 32 [2] 82 10 [2] 84 25 [2] aa 25 [2] 95 39 }

  condition:
    any of them
}
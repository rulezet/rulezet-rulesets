rule TTP_XOR_WriteProcessMemory_e713 {
  strings:
    $key_e713 = { b0 61 [2] 82 43 [2] 84 76 [2] aa 76 [2] 95 6a }

  condition:
    any of them
}
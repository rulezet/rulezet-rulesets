rule TTP_XOR_WriteProcessMemory_d889 {
  strings:
    $key_d889 = { 8f fb [2] bd d9 [2] bb ec [2] 95 ec [2] aa f0 }

  condition:
    any of them
}
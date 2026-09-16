rule TTP_XOR_WriteProcessMemory_e721 {
  strings:
    $key_e721 = { b0 53 [2] 82 71 [2] 84 44 [2] aa 44 [2] 95 58 }

  condition:
    any of them
}
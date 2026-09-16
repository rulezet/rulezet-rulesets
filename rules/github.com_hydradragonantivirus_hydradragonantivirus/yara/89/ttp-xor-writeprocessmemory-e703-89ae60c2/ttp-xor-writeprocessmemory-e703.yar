rule TTP_XOR_WriteProcessMemory_e703 {
  strings:
    $key_e703 = { b0 71 [2] 82 53 [2] 84 66 [2] aa 66 [2] 95 7a }

  condition:
    any of them
}
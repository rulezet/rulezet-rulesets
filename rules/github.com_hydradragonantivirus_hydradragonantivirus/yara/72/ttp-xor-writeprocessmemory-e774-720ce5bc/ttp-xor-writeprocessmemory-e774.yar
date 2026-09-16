rule TTP_XOR_WriteProcessMemory_e774 {
  strings:
    $key_e774 = { b0 06 [2] 82 24 [2] 84 11 [2] aa 11 [2] 95 0d }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_e766 {
  strings:
    $key_e766 = { b0 14 [2] 82 36 [2] 84 03 [2] aa 03 [2] 95 1f }

  condition:
    any of them
}
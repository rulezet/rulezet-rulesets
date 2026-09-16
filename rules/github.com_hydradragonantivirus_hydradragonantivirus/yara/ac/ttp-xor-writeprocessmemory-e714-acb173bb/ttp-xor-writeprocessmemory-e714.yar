rule TTP_XOR_WriteProcessMemory_e714 {
  strings:
    $key_e714 = { b0 66 [2] 82 44 [2] 84 71 [2] aa 71 [2] 95 6d }

  condition:
    any of them
}
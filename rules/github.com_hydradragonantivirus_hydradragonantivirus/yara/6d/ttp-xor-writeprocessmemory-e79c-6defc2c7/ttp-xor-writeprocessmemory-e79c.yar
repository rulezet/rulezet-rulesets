rule TTP_XOR_WriteProcessMemory_e79c {
  strings:
    $key_e79c = { b0 ee [2] 82 cc [2] 84 f9 [2] aa f9 [2] 95 e5 }

  condition:
    any of them
}
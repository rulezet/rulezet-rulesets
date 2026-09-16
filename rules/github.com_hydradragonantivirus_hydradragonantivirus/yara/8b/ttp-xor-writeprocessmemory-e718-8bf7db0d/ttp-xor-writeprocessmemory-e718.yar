rule TTP_XOR_WriteProcessMemory_e718 {
  strings:
    $key_e718 = { b0 6a [2] 82 48 [2] 84 7d [2] aa 7d [2] 95 61 }

  condition:
    any of them
}
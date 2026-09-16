rule TTP_XOR_WriteProcessMemory_e7f2 {
  strings:
    $key_e7f2 = { b0 80 [2] 82 a2 [2] 84 97 [2] aa 97 [2] 95 8b }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_e7d0 {
  strings:
    $key_e7d0 = { b0 a2 [2] 82 80 [2] 84 b5 [2] aa b5 [2] 95 a9 }

  condition:
    any of them
}
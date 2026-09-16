rule TTP_XOR_WriteProcessMemory_e7e1 {
  strings:
    $key_e7e1 = { b0 93 [2] 82 b1 [2] 84 84 [2] aa 84 [2] 95 98 }

  condition:
    any of them
}
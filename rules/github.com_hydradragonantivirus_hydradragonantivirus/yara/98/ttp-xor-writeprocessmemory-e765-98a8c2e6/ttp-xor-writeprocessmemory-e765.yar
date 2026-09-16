rule TTP_XOR_WriteProcessMemory_e765 {
  strings:
    $key_e765 = { b0 17 [2] 82 35 [2] 84 00 [2] aa 00 [2] 95 1c }

  condition:
    any of them
}
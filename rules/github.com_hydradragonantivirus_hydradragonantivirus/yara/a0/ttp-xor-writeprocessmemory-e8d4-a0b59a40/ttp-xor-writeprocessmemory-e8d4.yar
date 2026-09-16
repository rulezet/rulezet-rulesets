rule TTP_XOR_WriteProcessMemory_e8d4 {
  strings:
    $key_e8d4 = { bf a6 [2] 8d 84 [2] 8b b1 [2] a5 b1 [2] 9a ad }

  condition:
    any of them
}
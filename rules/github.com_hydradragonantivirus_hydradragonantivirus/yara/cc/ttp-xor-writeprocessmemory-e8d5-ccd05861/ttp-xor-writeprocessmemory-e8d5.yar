rule TTP_XOR_WriteProcessMemory_e8d5 {
  strings:
    $key_e8d5 = { bf a7 [2] 8d 85 [2] 8b b0 [2] a5 b0 [2] 9a ac }

  condition:
    any of them
}
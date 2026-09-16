rule TTP_XOR_WriteProcessMemory_cc85 {
  strings:
    $key_cc85 = { 9b f7 [2] a9 d5 [2] af e0 [2] 81 e0 [2] be fc }

  condition:
    any of them
}
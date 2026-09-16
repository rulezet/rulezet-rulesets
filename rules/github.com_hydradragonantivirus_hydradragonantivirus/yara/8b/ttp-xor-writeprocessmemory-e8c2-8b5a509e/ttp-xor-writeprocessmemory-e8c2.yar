rule TTP_XOR_WriteProcessMemory_e8c2 {
  strings:
    $key_e8c2 = { bf b0 [2] 8d 92 [2] 8b a7 [2] a5 a7 [2] 9a bb }

  condition:
    any of them
}
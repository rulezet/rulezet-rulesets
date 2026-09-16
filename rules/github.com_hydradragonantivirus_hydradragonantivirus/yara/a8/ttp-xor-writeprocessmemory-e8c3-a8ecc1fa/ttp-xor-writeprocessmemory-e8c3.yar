rule TTP_XOR_WriteProcessMemory_e8c3 {
  strings:
    $key_e8c3 = { bf b1 [2] 8d 93 [2] 8b a6 [2] a5 a6 [2] 9a ba }

  condition:
    any of them
}
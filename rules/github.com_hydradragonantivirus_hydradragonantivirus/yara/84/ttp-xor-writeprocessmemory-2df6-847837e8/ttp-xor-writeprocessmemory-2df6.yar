rule TTP_XOR_WriteProcessMemory_2df6 {
  strings:
    $key_2df6 = { 7a 84 [2] 48 a6 [2] 4e 93 [2] 60 93 [2] 5f 8f }

  condition:
    any of them
}
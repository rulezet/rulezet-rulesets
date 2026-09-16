rule TTP_XOR_WriteProcessMemory_db81 {
  strings:
    $key_db81 = { 8c f3 [2] be d1 [2] b8 e4 [2] 96 e4 [2] a9 f8 }

  condition:
    any of them
}
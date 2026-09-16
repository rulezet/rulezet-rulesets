rule TTP_XOR_WriteProcessMemory_73a4 {
  strings:
    $key_73a4 = { 24 d6 [2] 16 f4 [2] 10 c1 [2] 3e c1 [2] 01 dd }

  condition:
    any of them
}
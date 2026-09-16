rule TTP_XOR_WriteProcessMemory_73e4 {
  strings:
    $key_73e4 = { 24 96 [2] 16 b4 [2] 10 81 [2] 3e 81 [2] 01 9d }

  condition:
    any of them
}
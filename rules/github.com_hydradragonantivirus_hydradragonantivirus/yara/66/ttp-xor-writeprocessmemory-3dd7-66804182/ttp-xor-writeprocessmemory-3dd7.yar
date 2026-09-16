rule TTP_XOR_WriteProcessMemory_3dd7 {
  strings:
    $key_3dd7 = { 6a a5 [2] 58 87 [2] 5e b2 [2] 70 b2 [2] 4f ae }

  condition:
    any of them
}
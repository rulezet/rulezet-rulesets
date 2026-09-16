rule TTP_XOR_WriteProcessMemory_1dd7 {
  strings:
    $key_1dd7 = { 4a a5 [2] 78 87 [2] 7e b2 [2] 50 b2 [2] 6f ae }

  condition:
    any of them
}
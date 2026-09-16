rule TTP_XOR_WriteProcessMemory_73d7 {
  strings:
    $key_73d7 = { 24 a5 [2] 16 87 [2] 10 b2 [2] 3e b2 [2] 01 ae }

  condition:
    any of them
}
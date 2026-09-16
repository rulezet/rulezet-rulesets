rule TTP_XOR_WriteProcessMemory_fed7 {
  strings:
    $key_fed7 = { a9 a5 [2] 9b 87 [2] 9d b2 [2] b3 b2 [2] 8c ae }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_fed4 {
  strings:
    $key_fed4 = { a9 a6 [2] 9b 84 [2] 9d b1 [2] b3 b1 [2] 8c ad }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_eed7 {
  strings:
    $key_eed7 = { b9 a5 [2] 8b 87 [2] 8d b2 [2] a3 b2 [2] 9c ae }

  condition:
    any of them
}
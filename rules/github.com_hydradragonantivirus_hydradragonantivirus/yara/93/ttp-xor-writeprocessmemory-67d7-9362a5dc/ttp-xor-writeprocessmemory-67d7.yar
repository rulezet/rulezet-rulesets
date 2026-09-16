rule TTP_XOR_WriteProcessMemory_67d7 {
  strings:
    $key_67d7 = { 30 a5 [2] 02 87 [2] 04 b2 [2] 2a b2 [2] 15 ae }

  condition:
    any of them
}
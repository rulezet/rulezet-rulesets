rule TTP_XOR_WriteProcessMemory_27d7 {
  strings:
    $key_27d7 = { 70 a5 [2] 42 87 [2] 44 b2 [2] 6a b2 [2] 55 ae }

  condition:
    any of them
}
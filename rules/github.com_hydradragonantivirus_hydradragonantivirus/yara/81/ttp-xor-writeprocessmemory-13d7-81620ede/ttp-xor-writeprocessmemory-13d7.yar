rule TTP_XOR_WriteProcessMemory_13d7 {
  strings:
    $key_13d7 = { 44 a5 [2] 76 87 [2] 70 b2 [2] 5e b2 [2] 61 ae }

  condition:
    any of them
}
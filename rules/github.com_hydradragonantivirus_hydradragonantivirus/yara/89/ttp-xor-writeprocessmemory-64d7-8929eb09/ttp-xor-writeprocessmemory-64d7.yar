rule TTP_XOR_WriteProcessMemory_64d7 {
  strings:
    $key_64d7 = { 33 a5 [2] 01 87 [2] 07 b2 [2] 29 b2 [2] 16 ae }

  condition:
    any of them
}
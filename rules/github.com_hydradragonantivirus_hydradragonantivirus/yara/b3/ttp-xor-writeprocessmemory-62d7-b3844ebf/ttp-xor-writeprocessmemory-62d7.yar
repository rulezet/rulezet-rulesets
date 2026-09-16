rule TTP_XOR_WriteProcessMemory_62d7 {
  strings:
    $key_62d7 = { 35 a5 [2] 07 87 [2] 01 b2 [2] 2f b2 [2] 10 ae }

  condition:
    any of them
}
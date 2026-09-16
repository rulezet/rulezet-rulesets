rule TTP_XOR_WriteProcessMemory_40d7 {
  strings:
    $key_40d7 = { 17 a5 [2] 25 87 [2] 23 b2 [2] 0d b2 [2] 32 ae }

  condition:
    any of them
}
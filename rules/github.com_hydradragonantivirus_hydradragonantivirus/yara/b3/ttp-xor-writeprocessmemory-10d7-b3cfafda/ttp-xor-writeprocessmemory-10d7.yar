rule TTP_XOR_WriteProcessMemory_10d7 {
  strings:
    $key_10d7 = { 47 a5 [2] 75 87 [2] 73 b2 [2] 5d b2 [2] 62 ae }

  condition:
    any of them
}
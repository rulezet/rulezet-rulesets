rule TTP_XOR_WriteProcessMemory_16d7 {
  strings:
    $key_16d7 = { 41 a5 [2] 73 87 [2] 75 b2 [2] 5b b2 [2] 64 ae }

  condition:
    any of them
}
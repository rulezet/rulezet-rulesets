rule TTP_XOR_WriteProcessMemory_46d7 {
  strings:
    $key_46d7 = { 11 a5 [2] 23 87 [2] 25 b2 [2] 0b b2 [2] 34 ae }

  condition:
    any of them
}
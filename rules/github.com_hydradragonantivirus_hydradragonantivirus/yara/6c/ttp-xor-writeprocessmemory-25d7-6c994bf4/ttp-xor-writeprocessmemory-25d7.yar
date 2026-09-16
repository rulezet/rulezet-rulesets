rule TTP_XOR_WriteProcessMemory_25d7 {
  strings:
    $key_25d7 = { 72 a5 [2] 40 87 [2] 46 b2 [2] 68 b2 [2] 57 ae }

  condition:
    any of them
}
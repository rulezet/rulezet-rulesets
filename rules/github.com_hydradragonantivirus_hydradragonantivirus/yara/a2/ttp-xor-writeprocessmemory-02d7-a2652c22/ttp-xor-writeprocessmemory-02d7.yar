rule TTP_XOR_WriteProcessMemory_02d7 {
  strings:
    $key_02d7 = { 55 a5 [2] 67 87 [2] 61 b2 [2] 4f b2 [2] 70 ae }

  condition:
    any of them
}
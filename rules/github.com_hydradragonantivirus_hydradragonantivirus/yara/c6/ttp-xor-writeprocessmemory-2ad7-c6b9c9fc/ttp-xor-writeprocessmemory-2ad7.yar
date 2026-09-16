rule TTP_XOR_WriteProcessMemory_2ad7 {
  strings:
    $key_2ad7 = { 7d a5 [2] 4f 87 [2] 49 b2 [2] 67 b2 [2] 58 ae }

  condition:
    any of them
}
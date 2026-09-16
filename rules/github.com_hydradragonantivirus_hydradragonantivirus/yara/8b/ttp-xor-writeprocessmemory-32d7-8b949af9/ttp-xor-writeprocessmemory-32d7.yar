rule TTP_XOR_WriteProcessMemory_32d7 {
  strings:
    $key_32d7 = { 65 a5 [2] 57 87 [2] 51 b2 [2] 7f b2 [2] 40 ae }

  condition:
    any of them
}
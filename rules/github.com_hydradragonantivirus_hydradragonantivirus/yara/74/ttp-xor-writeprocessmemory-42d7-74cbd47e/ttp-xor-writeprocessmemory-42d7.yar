rule TTP_XOR_WriteProcessMemory_42d7 {
  strings:
    $key_42d7 = { 15 a5 [2] 27 87 [2] 21 b2 [2] 0f b2 [2] 30 ae }

  condition:
    any of them
}
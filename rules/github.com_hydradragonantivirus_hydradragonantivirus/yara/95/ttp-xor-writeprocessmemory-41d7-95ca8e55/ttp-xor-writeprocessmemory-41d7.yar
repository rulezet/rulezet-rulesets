rule TTP_XOR_WriteProcessMemory_41d7 {
  strings:
    $key_41d7 = { 16 a5 [2] 24 87 [2] 22 b2 [2] 0c b2 [2] 33 ae }

  condition:
    any of them
}
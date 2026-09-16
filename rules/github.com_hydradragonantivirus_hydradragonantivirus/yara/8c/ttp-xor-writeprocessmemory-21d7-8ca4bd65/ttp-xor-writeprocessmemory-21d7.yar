rule TTP_XOR_WriteProcessMemory_21d7 {
  strings:
    $key_21d7 = { 76 a5 [2] 44 87 [2] 42 b2 [2] 6c b2 [2] 53 ae }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_31d7 {
  strings:
    $key_31d7 = { 66 a5 [2] 54 87 [2] 52 b2 [2] 7c b2 [2] 43 ae }

  condition:
    any of them
}
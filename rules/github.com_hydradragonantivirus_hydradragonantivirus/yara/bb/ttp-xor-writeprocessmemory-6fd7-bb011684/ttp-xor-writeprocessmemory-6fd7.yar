rule TTP_XOR_WriteProcessMemory_6fd7 {
  strings:
    $key_6fd7 = { 38 a5 [2] 0a 87 [2] 0c b2 [2] 22 b2 [2] 1d ae }

  condition:
    any of them
}
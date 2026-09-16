rule TTP_XOR_WriteProcessMemory_5fd7 {
  strings:
    $key_5fd7 = { 08 a5 [2] 3a 87 [2] 3c b2 [2] 12 b2 [2] 2d ae }

  condition:
    any of them
}
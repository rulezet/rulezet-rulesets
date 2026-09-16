rule TTP_XOR_WriteProcessMemory_5fd0 {
  strings:
    $key_5fd0 = { 08 a2 [2] 3a 80 [2] 3c b5 [2] 12 b5 [2] 2d a9 }

  condition:
    any of them
}
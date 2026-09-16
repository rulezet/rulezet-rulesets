rule TTP_XOR_WriteProcessMemory_21d1 {
  strings:
    $key_21d1 = { 76 a3 [2] 44 81 [2] 42 b4 [2] 6c b4 [2] 53 a8 }

  condition:
    any of them
}
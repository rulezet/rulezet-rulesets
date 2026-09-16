rule TTP_XOR_WriteProcessMemory_31d1 {
  strings:
    $key_31d1 = { 66 a3 [2] 54 81 [2] 52 b4 [2] 7c b4 [2] 43 a8 }

  condition:
    any of them
}
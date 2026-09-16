rule TTP_XOR_WriteProcessMemory_11d1 {
  strings:
    $key_11d1 = { 46 a3 [2] 74 81 [2] 72 b4 [2] 5c b4 [2] 63 a8 }

  condition:
    any of them
}
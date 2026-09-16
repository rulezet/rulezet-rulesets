rule TTP_XOR_WriteProcessMemory_11d4 {
  strings:
    $key_11d4 = { 46 a6 [2] 74 84 [2] 72 b1 [2] 5c b1 [2] 63 ad }

  condition:
    any of them
}
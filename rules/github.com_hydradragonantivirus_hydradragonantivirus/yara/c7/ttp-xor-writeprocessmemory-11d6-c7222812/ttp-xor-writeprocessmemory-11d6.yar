rule TTP_XOR_WriteProcessMemory_11d6 {
  strings:
    $key_11d6 = { 46 a4 [2] 74 86 [2] 72 b3 [2] 5c b3 [2] 63 af }

  condition:
    any of them
}
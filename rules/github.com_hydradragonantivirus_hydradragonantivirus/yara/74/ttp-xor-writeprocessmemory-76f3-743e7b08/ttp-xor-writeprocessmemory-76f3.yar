rule TTP_XOR_WriteProcessMemory_76f3 {
  strings:
    $key_76f3 = { 21 81 [2] 13 a3 [2] 15 96 [2] 3b 96 [2] 04 8a }

  condition:
    any of them
}
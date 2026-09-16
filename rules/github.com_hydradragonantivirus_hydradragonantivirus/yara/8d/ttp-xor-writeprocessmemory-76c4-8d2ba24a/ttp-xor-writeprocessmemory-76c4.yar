rule TTP_XOR_WriteProcessMemory_76c4 {
  strings:
    $key_76c4 = { 21 b6 [2] 13 94 [2] 15 a1 [2] 3b a1 [2] 04 bd }

  condition:
    any of them
}
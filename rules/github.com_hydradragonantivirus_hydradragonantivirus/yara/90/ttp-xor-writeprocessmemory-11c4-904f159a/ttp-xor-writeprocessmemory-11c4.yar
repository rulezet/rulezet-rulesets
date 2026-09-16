rule TTP_XOR_WriteProcessMemory_11c4 {
  strings:
    $key_11c4 = { 46 b6 [2] 74 94 [2] 72 a1 [2] 5c a1 [2] 63 bd }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_7fc4 {
  strings:
    $key_7fc4 = { 28 b6 [2] 1a 94 [2] 1c a1 [2] 32 a1 [2] 0d bd }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_13c4 {
  strings:
    $key_13c4 = { 44 b6 [2] 76 94 [2] 70 a1 [2] 5e a1 [2] 61 bd }

  condition:
    any of them
}
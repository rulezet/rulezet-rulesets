rule TTP_XOR_WriteProcessMemory_52c4 {
  strings:
    $key_52c4 = { 05 b6 [2] 37 94 [2] 31 a1 [2] 1f a1 [2] 20 bd }

  condition:
    any of them
}
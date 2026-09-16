rule TTP_XOR_WriteProcessMemory_3dc4 {
  strings:
    $key_3dc4 = { 6a b6 [2] 58 94 [2] 5e a1 [2] 70 a1 [2] 4f bd }

  condition:
    any of them
}
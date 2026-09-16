rule TTP_XOR_WriteProcessMemory_6dc4 {
  strings:
    $key_6dc4 = { 3a b6 [2] 08 94 [2] 0e a1 [2] 20 a1 [2] 1f bd }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_ee96 {
  strings:
    $key_ee96 = { b9 e4 [2] 8b c6 [2] 8d f3 [2] a3 f3 [2] 9c ef }

  condition:
    any of them
}
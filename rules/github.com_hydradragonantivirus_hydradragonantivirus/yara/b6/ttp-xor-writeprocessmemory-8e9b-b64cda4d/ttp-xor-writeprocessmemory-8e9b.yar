rule TTP_XOR_WriteProcessMemory_8e9b {
  strings:
    $key_8e9b = { d9 e9 [2] eb cb [2] ed fe [2] c3 fe [2] fc e2 }

  condition:
    any of them
}
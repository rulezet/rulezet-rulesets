rule TTP_XOR_WriteProcessMemory_8e85 {
  strings:
    $key_8e85 = { d9 f7 [2] eb d5 [2] ed e0 [2] c3 e0 [2] fc fc }

  condition:
    any of them
}
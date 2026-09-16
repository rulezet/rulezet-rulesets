rule TTP_XOR_WriteProcessMemory_8e82 {
  strings:
    $key_8e82 = { d9 f0 [2] eb d2 [2] ed e7 [2] c3 e7 [2] fc fb }

  condition:
    any of them
}
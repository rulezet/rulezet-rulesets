rule TTP_XOR_WriteProcessMemory_8e8c {
  strings:
    $key_8e8c = { d9 fe [2] eb dc [2] ed e9 [2] c3 e9 [2] fc f5 }

  condition:
    any of them
}
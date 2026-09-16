rule TTP_XOR_WriteProcessMemory_8e83 {
  strings:
    $key_8e83 = { d9 f1 [2] eb d3 [2] ed e6 [2] c3 e6 [2] fc fa }

  condition:
    any of them
}
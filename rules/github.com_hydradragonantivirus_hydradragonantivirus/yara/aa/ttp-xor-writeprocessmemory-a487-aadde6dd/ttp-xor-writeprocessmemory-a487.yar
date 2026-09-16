rule TTP_XOR_WriteProcessMemory_a487 {
  strings:
    $key_a487 = { f3 f5 [2] c1 d7 [2] c7 e2 [2] e9 e2 [2] d6 fe }

  condition:
    any of them
}
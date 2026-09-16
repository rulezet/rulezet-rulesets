rule TTP_XOR_WriteProcessMemory_a687 {
  strings:
    $key_a687 = { f1 f5 [2] c3 d7 [2] c5 e2 [2] eb e2 [2] d4 fe }

  condition:
    any of them
}
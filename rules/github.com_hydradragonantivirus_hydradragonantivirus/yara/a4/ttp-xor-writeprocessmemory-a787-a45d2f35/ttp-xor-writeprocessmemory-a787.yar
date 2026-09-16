rule TTP_XOR_WriteProcessMemory_a787 {
  strings:
    $key_a787 = { f0 f5 [2] c2 d7 [2] c4 e2 [2] ea e2 [2] d5 fe }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_a693 {
  strings:
    $key_a693 = { f1 e1 [2] c3 c3 [2] c5 f6 [2] eb f6 [2] d4 ea }

  condition:
    any of them
}
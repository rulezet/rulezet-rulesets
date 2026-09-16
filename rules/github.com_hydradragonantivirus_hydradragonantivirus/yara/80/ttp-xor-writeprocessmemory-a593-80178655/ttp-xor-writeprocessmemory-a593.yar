rule TTP_XOR_WriteProcessMemory_a593 {
  strings:
    $key_a593 = { f2 e1 [2] c0 c3 [2] c6 f6 [2] e8 f6 [2] d7 ea }

  condition:
    any of them
}
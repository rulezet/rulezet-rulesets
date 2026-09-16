rule TTP_XOR_WriteProcessMemory_a6b5 {
  strings:
    $key_a6b5 = { f1 c7 [2] c3 e5 [2] c5 d0 [2] eb d0 [2] d4 cc }

  condition:
    any of them
}
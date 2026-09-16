rule TTP_XOR_WriteProcessMemory_a48c {
  strings:
    $key_a48c = { f3 fe [2] c1 dc [2] c7 e9 [2] e9 e9 [2] d6 f5 }

  condition:
    any of them
}
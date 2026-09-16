rule TTP_XOR_WriteProcessMemory_b48c {
  strings:
    $key_b48c = { e3 fe [2] d1 dc [2] d7 e9 [2] f9 e9 [2] c6 f5 }

  condition:
    any of them
}
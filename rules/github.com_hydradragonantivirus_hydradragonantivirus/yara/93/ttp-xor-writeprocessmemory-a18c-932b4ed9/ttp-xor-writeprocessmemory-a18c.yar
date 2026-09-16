rule TTP_XOR_WriteProcessMemory_a18c {
  strings:
    $key_a18c = { f6 fe [2] c4 dc [2] c2 e9 [2] ec e9 [2] d3 f5 }

  condition:
    any of them
}
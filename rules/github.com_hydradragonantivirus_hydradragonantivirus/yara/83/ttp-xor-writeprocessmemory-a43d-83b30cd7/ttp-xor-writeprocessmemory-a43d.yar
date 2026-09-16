rule TTP_XOR_WriteProcessMemory_a43d {
  strings:
    $key_a43d = { f3 4f [2] c1 6d [2] c7 58 [2] e9 58 [2] d6 44 }

  condition:
    any of them
}
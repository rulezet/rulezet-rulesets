rule TTP_XOR_WriteProcessMemory_a69d {
  strings:
    $key_a69d = { f1 ef [2] c3 cd [2] c5 f8 [2] eb f8 [2] d4 e4 }

  condition:
    any of them
}
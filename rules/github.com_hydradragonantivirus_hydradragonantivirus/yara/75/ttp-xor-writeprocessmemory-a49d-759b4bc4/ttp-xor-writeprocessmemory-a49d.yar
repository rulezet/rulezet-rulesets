rule TTP_XOR_WriteProcessMemory_a49d {
  strings:
    $key_a49d = { f3 ef [2] c1 cd [2] c7 f8 [2] e9 f8 [2] d6 e4 }

  condition:
    any of them
}
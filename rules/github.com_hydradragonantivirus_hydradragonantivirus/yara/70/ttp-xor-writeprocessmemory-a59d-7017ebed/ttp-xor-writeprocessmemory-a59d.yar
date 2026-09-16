rule TTP_XOR_WriteProcessMemory_a59d {
  strings:
    $key_a59d = { f2 ef [2] c0 cd [2] c6 f8 [2] e8 f8 [2] d7 e4 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_959d {
  strings:
    $key_959d = { c2 ef [2] f0 cd [2] f6 f8 [2] d8 f8 [2] e7 e4 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_909d {
  strings:
    $key_909d = { c7 ef [2] f5 cd [2] f3 f8 [2] dd f8 [2] e2 e4 }

  condition:
    any of them
}
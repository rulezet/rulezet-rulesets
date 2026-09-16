rule TTP_XOR_WriteProcessMemory_819d {
  strings:
    $key_819d = { d6 ef [2] e4 cd [2] e2 f8 [2] cc f8 [2] f3 e4 }

  condition:
    any of them
}
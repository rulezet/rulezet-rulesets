rule TTP_XOR_WriteProcessMemory_949d {
  strings:
    $key_949d = { c3 ef [2] f1 cd [2] f7 f8 [2] d9 f8 [2] e6 e4 }

  condition:
    any of them
}
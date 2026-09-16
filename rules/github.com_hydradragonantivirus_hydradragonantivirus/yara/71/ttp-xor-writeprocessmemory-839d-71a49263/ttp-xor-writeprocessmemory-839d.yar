rule TTP_XOR_WriteProcessMemory_839d {
  strings:
    $key_839d = { d4 ef [2] e6 cd [2] e0 f8 [2] ce f8 [2] f1 e4 }

  condition:
    any of them
}
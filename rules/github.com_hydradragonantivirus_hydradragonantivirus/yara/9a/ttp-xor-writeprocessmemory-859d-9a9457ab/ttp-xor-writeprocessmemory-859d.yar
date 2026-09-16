rule TTP_XOR_WriteProcessMemory_859d {
  strings:
    $key_859d = { d2 ef [2] e0 cd [2] e6 f8 [2] c8 f8 [2] f7 e4 }

  condition:
    any of them
}
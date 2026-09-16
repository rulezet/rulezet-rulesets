rule TTP_XOR_WriteProcessMemory_8a9d {
  strings:
    $key_8a9d = { dd ef [2] ef cd [2] e9 f8 [2] c7 f8 [2] f8 e4 }

  condition:
    any of them
}
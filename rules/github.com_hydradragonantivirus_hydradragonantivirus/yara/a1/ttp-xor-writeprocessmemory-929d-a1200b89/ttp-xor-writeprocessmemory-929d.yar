rule TTP_XOR_WriteProcessMemory_929d {
  strings:
    $key_929d = { c5 ef [2] f7 cd [2] f1 f8 [2] df f8 [2] e0 e4 }

  condition:
    any of them
}
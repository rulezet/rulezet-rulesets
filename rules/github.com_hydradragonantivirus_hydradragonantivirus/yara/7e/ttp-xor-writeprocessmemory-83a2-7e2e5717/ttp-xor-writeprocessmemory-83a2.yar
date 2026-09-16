rule TTP_XOR_WriteProcessMemory_83a2 {
  strings:
    $key_83a2 = { d4 d0 [2] e6 f2 [2] e0 c7 [2] ce c7 [2] f1 db }

  condition:
    any of them
}
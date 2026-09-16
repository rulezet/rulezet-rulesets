rule TTP_XOR_WriteProcessMemory_87a2 {
  strings:
    $key_87a2 = { d0 d0 [2] e2 f2 [2] e4 c7 [2] ca c7 [2] f5 db }

  condition:
    any of them
}
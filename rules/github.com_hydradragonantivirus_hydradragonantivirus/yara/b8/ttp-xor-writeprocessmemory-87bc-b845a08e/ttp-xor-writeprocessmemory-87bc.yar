rule TTP_XOR_WriteProcessMemory_87bc {
  strings:
    $key_87bc = { d0 ce [2] e2 ec [2] e4 d9 [2] ca d9 [2] f5 c5 }

  condition:
    any of them
}
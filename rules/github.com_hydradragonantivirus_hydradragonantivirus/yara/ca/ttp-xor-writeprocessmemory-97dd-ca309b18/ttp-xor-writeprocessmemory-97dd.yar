rule TTP_XOR_WriteProcessMemory_97dd {
  strings:
    $key_97dd = { c0 af [2] f2 8d [2] f4 b8 [2] da b8 [2] e5 a4 }

  condition:
    any of them
}
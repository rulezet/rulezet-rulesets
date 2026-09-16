rule TTP_XOR_WriteProcessMemory_82dd {
  strings:
    $key_82dd = { d5 af [2] e7 8d [2] e1 b8 [2] cf b8 [2] f0 a4 }

  condition:
    any of them
}
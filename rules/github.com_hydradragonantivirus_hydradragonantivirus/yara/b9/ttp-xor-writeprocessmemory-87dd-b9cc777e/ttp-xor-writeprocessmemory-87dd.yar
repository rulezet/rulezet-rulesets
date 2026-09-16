rule TTP_XOR_WriteProcessMemory_87dd {
  strings:
    $key_87dd = { d0 af [2] e2 8d [2] e4 b8 [2] ca b8 [2] f5 a4 }

  condition:
    any of them
}
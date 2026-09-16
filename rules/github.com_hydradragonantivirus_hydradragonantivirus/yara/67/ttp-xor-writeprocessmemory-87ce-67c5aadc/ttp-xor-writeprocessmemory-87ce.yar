rule TTP_XOR_WriteProcessMemory_87ce {
  strings:
    $key_87ce = { d0 bc [2] e2 9e [2] e4 ab [2] ca ab [2] f5 b7 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_938c {
  strings:
    $key_938c = { c4 fe [2] f6 dc [2] f0 e9 [2] de e9 [2] e1 f5 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_b89b {
  strings:
    $key_b89b = { ef e9 [2] dd cb [2] db fe [2] f5 fe [2] ca e2 }

  condition:
    any of them
}
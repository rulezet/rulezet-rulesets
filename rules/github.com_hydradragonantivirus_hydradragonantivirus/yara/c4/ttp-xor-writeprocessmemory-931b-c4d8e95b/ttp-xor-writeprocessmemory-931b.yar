rule TTP_XOR_WriteProcessMemory_931b {
  strings:
    $key_931b = { c4 69 [2] f6 4b [2] f0 7e [2] de 7e [2] e1 62 }

  condition:
    any of them
}
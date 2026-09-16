rule TTP_XOR_WriteProcessMemory_935b {
  strings:
    $key_935b = { c4 29 [2] f6 0b [2] f0 3e [2] de 3e [2] e1 22 }

  condition:
    any of them
}
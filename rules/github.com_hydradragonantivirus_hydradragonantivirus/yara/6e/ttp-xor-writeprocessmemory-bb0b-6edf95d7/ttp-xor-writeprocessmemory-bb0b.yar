rule TTP_XOR_WriteProcessMemory_bb0b {
  strings:
    $key_bb0b = { ec 79 [2] de 5b [2] d8 6e [2] f6 6e [2] c9 72 }

  condition:
    any of them
}
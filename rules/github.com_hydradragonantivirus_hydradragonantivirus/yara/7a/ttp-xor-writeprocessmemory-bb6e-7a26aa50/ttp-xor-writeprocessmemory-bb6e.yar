rule TTP_XOR_WriteProcessMemory_bb6e {
  strings:
    $key_bb6e = { ec 1c [2] de 3e [2] d8 0b [2] f6 0b [2] c9 17 }

  condition:
    any of them
}
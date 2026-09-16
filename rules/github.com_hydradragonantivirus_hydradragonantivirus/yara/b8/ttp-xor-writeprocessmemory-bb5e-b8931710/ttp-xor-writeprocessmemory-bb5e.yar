rule TTP_XOR_WriteProcessMemory_bb5e {
  strings:
    $key_bb5e = { ec 2c [2] de 0e [2] d8 3b [2] f6 3b [2] c9 27 }

  condition:
    any of them
}
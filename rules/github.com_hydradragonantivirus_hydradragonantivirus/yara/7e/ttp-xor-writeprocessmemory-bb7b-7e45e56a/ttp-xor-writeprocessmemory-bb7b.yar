rule TTP_XOR_WriteProcessMemory_bb7b {
  strings:
    $key_bb7b = { ec 09 [2] de 2b [2] d8 1e [2] f6 1e [2] c9 02 }

  condition:
    any of them
}
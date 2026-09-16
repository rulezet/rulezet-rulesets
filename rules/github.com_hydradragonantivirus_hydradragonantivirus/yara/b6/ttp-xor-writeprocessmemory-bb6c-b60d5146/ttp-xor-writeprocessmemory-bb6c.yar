rule TTP_XOR_WriteProcessMemory_bb6c {
  strings:
    $key_bb6c = { ec 1e [2] de 3c [2] d8 09 [2] f6 09 [2] c9 15 }

  condition:
    any of them
}
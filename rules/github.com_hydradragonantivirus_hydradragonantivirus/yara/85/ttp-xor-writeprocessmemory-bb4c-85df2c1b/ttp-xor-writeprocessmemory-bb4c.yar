rule TTP_XOR_WriteProcessMemory_bb4c {
  strings:
    $key_bb4c = { ec 3e [2] de 1c [2] d8 29 [2] f6 29 [2] c9 35 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_bb1c {
  strings:
    $key_bb1c = { ec 6e [2] de 4c [2] d8 79 [2] f6 79 [2] c9 65 }

  condition:
    any of them
}
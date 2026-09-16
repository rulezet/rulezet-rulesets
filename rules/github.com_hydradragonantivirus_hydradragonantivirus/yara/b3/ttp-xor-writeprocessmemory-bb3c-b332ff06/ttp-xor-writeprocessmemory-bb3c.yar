rule TTP_XOR_WriteProcessMemory_bb3c {
  strings:
    $key_bb3c = { ec 4e [2] de 6c [2] d8 59 [2] f6 59 [2] c9 45 }

  condition:
    any of them
}
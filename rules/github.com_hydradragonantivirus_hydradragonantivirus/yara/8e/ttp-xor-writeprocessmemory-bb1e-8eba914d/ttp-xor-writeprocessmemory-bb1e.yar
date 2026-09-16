rule TTP_XOR_WriteProcessMemory_bb1e {
  strings:
    $key_bb1e = { ec 6c [2] de 4e [2] d8 7b [2] f6 7b [2] c9 67 }

  condition:
    any of them
}
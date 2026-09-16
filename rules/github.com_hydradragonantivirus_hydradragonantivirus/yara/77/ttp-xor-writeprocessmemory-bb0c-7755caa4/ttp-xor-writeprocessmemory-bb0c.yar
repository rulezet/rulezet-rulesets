rule TTP_XOR_WriteProcessMemory_bb0c {
  strings:
    $key_bb0c = { ec 7e [2] de 5c [2] d8 69 [2] f6 69 [2] c9 75 }

  condition:
    any of them
}
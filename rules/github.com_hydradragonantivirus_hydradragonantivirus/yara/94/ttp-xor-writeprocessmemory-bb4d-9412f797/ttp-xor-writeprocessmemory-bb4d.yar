rule TTP_XOR_WriteProcessMemory_bb4d {
  strings:
    $key_bb4d = { ec 3f [2] de 1d [2] d8 28 [2] f6 28 [2] c9 34 }

  condition:
    any of them
}
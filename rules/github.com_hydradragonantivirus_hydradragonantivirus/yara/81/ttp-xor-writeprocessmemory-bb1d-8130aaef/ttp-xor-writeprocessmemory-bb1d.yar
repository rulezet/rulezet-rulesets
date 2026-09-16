rule TTP_XOR_WriteProcessMemory_bb1d {
  strings:
    $key_bb1d = { ec 6f [2] de 4d [2] d8 78 [2] f6 78 [2] c9 64 }

  condition:
    any of them
}
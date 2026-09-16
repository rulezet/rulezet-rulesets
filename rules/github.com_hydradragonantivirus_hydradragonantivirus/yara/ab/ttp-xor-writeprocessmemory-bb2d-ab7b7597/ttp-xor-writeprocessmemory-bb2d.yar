rule TTP_XOR_WriteProcessMemory_bb2d {
  strings:
    $key_bb2d = { ec 5f [2] de 7d [2] d8 48 [2] f6 48 [2] c9 54 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_bb48 {
  strings:
    $key_bb48 = { ec 3a [2] de 18 [2] d8 2d [2] f6 2d [2] c9 31 }

  condition:
    any of them
}
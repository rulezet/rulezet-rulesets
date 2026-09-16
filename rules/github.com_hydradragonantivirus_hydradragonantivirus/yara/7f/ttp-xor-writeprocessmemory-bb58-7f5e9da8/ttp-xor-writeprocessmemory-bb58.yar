rule TTP_XOR_WriteProcessMemory_bb58 {
  strings:
    $key_bb58 = { ec 2a [2] de 08 [2] d8 3d [2] f6 3d [2] c9 21 }

  condition:
    any of them
}
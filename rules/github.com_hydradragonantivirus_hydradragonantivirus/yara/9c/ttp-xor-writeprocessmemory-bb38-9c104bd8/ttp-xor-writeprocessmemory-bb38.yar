rule TTP_XOR_WriteProcessMemory_bb38 {
  strings:
    $key_bb38 = { ec 4a [2] de 68 [2] d8 5d [2] f6 5d [2] c9 41 }

  condition:
    any of them
}
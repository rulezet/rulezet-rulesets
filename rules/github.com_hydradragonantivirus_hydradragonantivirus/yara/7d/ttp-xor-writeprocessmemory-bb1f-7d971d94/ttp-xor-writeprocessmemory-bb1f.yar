rule TTP_XOR_WriteProcessMemory_bb1f {
  strings:
    $key_bb1f = { ec 6d [2] de 4f [2] d8 7a [2] f6 7a [2] c9 66 }

  condition:
    any of them
}
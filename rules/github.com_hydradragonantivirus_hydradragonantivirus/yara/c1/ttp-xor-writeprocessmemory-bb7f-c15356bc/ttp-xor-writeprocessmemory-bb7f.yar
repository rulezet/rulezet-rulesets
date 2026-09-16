rule TTP_XOR_WriteProcessMemory_bb7f {
  strings:
    $key_bb7f = { ec 0d [2] de 2f [2] d8 1a [2] f6 1a [2] c9 06 }

  condition:
    any of them
}
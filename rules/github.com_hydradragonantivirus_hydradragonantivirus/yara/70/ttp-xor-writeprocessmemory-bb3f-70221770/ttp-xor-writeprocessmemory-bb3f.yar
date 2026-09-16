rule TTP_XOR_WriteProcessMemory_bb3f {
  strings:
    $key_bb3f = { ec 4d [2] de 6f [2] d8 5a [2] f6 5a [2] c9 46 }

  condition:
    any of them
}
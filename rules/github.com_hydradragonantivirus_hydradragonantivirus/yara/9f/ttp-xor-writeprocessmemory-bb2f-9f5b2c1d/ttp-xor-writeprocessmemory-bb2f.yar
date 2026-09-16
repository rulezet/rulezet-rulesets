rule TTP_XOR_WriteProcessMemory_bb2f {
  strings:
    $key_bb2f = { ec 5d [2] de 7f [2] d8 4a [2] f6 4a [2] c9 56 }

  condition:
    any of them
}
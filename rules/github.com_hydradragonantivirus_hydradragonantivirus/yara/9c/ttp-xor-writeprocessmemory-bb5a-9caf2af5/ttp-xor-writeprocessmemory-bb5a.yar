rule TTP_XOR_WriteProcessMemory_bb5a {
  strings:
    $key_bb5a = { ec 28 [2] de 0a [2] d8 3f [2] f6 3f [2] c9 23 }

  condition:
    any of them
}
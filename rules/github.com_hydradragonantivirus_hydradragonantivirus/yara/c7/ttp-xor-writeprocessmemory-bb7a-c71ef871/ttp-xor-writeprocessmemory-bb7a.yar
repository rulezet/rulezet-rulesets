rule TTP_XOR_WriteProcessMemory_bb7a {
  strings:
    $key_bb7a = { ec 08 [2] de 2a [2] d8 1f [2] f6 1f [2] c9 03 }

  condition:
    any of them
}
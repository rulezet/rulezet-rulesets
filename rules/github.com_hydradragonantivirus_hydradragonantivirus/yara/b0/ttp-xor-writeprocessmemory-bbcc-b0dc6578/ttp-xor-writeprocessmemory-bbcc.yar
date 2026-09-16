rule TTP_XOR_WriteProcessMemory_bbcc {
  strings:
    $key_bbcc = { ec be [2] de 9c [2] d8 a9 [2] f6 a9 [2] c9 b5 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_bbbe {
  strings:
    $key_bbbe = { ec cc [2] de ee [2] d8 db [2] f6 db [2] c9 c7 }

  condition:
    any of them
}
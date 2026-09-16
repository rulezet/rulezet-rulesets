rule TTP_XOR_WriteProcessMemory_93be {
  strings:
    $key_93be = { c4 cc [2] f6 ee [2] f0 db [2] de db [2] e1 c7 }

  condition:
    any of them
}
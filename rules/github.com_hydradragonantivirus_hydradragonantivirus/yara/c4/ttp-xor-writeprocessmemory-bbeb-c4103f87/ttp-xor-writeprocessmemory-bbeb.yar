rule TTP_XOR_WriteProcessMemory_bbeb {
  strings:
    $key_bbeb = { ec 99 [2] de bb [2] d8 8e [2] f6 8e [2] c9 92 }

  condition:
    any of them
}
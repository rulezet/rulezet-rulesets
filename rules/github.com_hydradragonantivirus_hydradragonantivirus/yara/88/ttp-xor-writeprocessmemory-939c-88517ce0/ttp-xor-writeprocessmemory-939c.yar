rule TTP_XOR_WriteProcessMemory_939c {
  strings:
    $key_939c = { c4 ee [2] f6 cc [2] f0 f9 [2] de f9 [2] e1 e5 }

  condition:
    any of them
}
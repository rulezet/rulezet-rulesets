rule TTP_XOR_WriteProcessMemory_bb24 {
  strings:
    $key_bb24 = { ec 56 [2] de 74 [2] d8 41 [2] f6 41 [2] c9 5d }

  condition:
    any of them
}
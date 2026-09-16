rule TTP_XOR_WriteProcessMemory_bb11 {
  strings:
    $key_bb11 = { ec 63 [2] de 41 [2] d8 74 [2] f6 74 [2] c9 68 }

  condition:
    any of them
}
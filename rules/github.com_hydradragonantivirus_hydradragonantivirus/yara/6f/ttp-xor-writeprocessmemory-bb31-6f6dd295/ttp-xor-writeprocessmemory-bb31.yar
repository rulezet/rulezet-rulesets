rule TTP_XOR_WriteProcessMemory_bb31 {
  strings:
    $key_bb31 = { ec 43 [2] de 61 [2] d8 54 [2] f6 54 [2] c9 48 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_bb51 {
  strings:
    $key_bb51 = { ec 23 [2] de 01 [2] d8 34 [2] f6 34 [2] c9 28 }

  condition:
    any of them
}
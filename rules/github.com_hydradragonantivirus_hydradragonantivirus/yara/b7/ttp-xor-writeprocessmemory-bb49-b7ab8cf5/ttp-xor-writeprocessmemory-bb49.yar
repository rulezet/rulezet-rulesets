rule TTP_XOR_WriteProcessMemory_bb49 {
  strings:
    $key_bb49 = { ec 3b [2] de 19 [2] d8 2c [2] f6 2c [2] c9 30 }

  condition:
    any of them
}
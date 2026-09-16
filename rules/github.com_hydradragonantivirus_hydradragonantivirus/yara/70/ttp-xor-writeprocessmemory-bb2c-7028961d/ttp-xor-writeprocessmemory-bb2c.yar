rule TTP_XOR_WriteProcessMemory_bb2c {
  strings:
    $key_bb2c = { ec 5e [2] de 7c [2] d8 49 [2] f6 49 [2] c9 55 }

  condition:
    any of them
}
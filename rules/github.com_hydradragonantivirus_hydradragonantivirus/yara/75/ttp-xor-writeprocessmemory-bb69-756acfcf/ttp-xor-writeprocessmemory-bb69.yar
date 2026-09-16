rule TTP_XOR_WriteProcessMemory_bb69 {
  strings:
    $key_bb69 = { ec 1b [2] de 39 [2] d8 0c [2] f6 0c [2] c9 10 }

  condition:
    any of them
}
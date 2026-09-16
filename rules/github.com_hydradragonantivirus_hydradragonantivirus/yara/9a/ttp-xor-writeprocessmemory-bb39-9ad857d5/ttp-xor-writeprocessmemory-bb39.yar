rule TTP_XOR_WriteProcessMemory_bb39 {
  strings:
    $key_bb39 = { ec 4b [2] de 69 [2] d8 5c [2] f6 5c [2] c9 40 }

  condition:
    any of them
}
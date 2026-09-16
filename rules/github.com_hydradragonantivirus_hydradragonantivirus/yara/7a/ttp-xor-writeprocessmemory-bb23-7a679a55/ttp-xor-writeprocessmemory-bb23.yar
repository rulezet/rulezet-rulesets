rule TTP_XOR_WriteProcessMemory_bb23 {
  strings:
    $key_bb23 = { ec 51 [2] de 73 [2] d8 46 [2] f6 46 [2] c9 5a }

  condition:
    any of them
}
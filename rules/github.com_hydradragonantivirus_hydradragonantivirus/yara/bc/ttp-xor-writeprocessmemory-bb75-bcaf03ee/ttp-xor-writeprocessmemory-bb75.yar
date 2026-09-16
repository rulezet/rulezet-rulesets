rule TTP_XOR_WriteProcessMemory_bb75 {
  strings:
    $key_bb75 = { ec 07 [2] de 25 [2] d8 10 [2] f6 10 [2] c9 0c }

  condition:
    any of them
}
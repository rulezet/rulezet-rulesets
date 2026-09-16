rule TTP_XOR_WriteProcessMemory_bb35 {
  strings:
    $key_bb35 = { ec 47 [2] de 65 [2] d8 50 [2] f6 50 [2] c9 4c }

  condition:
    any of them
}
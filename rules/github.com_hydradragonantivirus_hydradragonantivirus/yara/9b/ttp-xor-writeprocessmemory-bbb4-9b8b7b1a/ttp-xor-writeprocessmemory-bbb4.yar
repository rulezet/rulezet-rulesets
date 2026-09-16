rule TTP_XOR_WriteProcessMemory_bbb4 {
  strings:
    $key_bbb4 = { ec c6 [2] de e4 [2] d8 d1 [2] f6 d1 [2] c9 cd }

  condition:
    any of them
}
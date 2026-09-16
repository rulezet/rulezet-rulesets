rule TTP_XOR_WriteProcessMemory_bbb8 {
  strings:
    $key_bbb8 = { ec ca [2] de e8 [2] d8 dd [2] f6 dd [2] c9 c1 }

  condition:
    any of them
}
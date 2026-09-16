rule TTP_XOR_WriteProcessMemory_aac7 {
  strings:
    $key_aac7 = { fd b5 [2] cf 97 [2] c9 a2 [2] e7 a2 [2] d8 be }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_aac1 {
  strings:
    $key_aac1 = { fd b3 [2] cf 91 [2] c9 a4 [2] e7 a4 [2] d8 b8 }

  condition:
    any of them
}
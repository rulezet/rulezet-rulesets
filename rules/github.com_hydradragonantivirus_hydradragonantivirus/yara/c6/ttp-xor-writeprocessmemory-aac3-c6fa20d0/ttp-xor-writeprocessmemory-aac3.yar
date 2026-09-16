rule TTP_XOR_WriteProcessMemory_aac3 {
  strings:
    $key_aac3 = { fd b1 [2] cf 93 [2] c9 a6 [2] e7 a6 [2] d8 ba }

  condition:
    any of them
}
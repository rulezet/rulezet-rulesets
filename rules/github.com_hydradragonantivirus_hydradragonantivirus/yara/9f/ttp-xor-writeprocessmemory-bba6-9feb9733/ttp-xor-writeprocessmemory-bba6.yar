rule TTP_XOR_WriteProcessMemory_bba6 {
  strings:
    $key_bba6 = { ec d4 [2] de f6 [2] d8 c3 [2] f6 c3 [2] c9 df }

  condition:
    any of them
}
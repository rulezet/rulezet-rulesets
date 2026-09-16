rule TTP_XOR_WriteProcessMemory_bde3 {
  strings:
    $key_bde3 = { ea 91 [2] d8 b3 [2] de 86 [2] f0 86 [2] cf 9a }

  condition:
    any of them
}
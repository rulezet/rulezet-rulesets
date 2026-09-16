rule TTP_XOR_WriteProcessMemory_aa36 {
  strings:
    $key_aa36 = { fd 44 [2] cf 66 [2] c9 53 [2] e7 53 [2] d8 4f }

  condition:
    any of them
}
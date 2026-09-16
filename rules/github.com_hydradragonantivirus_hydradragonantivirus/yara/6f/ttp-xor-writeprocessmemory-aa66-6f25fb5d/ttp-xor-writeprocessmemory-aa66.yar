rule TTP_XOR_WriteProcessMemory_aa66 {
  strings:
    $key_aa66 = { fd 14 [2] cf 36 [2] c9 03 [2] e7 03 [2] d8 1f }

  condition:
    any of them
}
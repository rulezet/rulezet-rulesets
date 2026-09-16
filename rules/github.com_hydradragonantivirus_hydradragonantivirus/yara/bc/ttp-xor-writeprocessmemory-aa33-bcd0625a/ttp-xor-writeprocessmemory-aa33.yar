rule TTP_XOR_WriteProcessMemory_aa33 {
  strings:
    $key_aa33 = { fd 41 [2] cf 63 [2] c9 56 [2] e7 56 [2] d8 4a }

  condition:
    any of them
}
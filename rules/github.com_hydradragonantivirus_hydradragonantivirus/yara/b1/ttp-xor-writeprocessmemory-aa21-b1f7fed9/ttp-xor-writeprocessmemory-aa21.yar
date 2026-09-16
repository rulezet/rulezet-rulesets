rule TTP_XOR_WriteProcessMemory_aa21 {
  strings:
    $key_aa21 = { fd 53 [2] cf 71 [2] c9 44 [2] e7 44 [2] d8 58 }

  condition:
    any of them
}
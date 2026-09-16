rule TTP_XOR_WriteProcessMemory_aa61 {
  strings:
    $key_aa61 = { fd 13 [2] cf 31 [2] c9 04 [2] e7 04 [2] d8 18 }

  condition:
    any of them
}
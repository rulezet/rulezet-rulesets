rule TTP_XOR_WriteProcessMemory_aa24 {
  strings:
    $key_aa24 = { fd 56 [2] cf 74 [2] c9 41 [2] e7 41 [2] d8 5d }

  condition:
    any of them
}
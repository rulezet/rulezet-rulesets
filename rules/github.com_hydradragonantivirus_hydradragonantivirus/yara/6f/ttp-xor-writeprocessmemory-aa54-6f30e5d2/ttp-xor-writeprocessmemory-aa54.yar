rule TTP_XOR_WriteProcessMemory_aa54 {
  strings:
    $key_aa54 = { fd 26 [2] cf 04 [2] c9 31 [2] e7 31 [2] d8 2d }

  condition:
    any of them
}
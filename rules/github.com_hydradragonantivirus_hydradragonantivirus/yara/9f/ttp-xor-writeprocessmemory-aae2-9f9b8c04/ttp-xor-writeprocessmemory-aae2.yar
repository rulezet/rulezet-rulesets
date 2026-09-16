rule TTP_XOR_WriteProcessMemory_aae2 {
  strings:
    $key_aae2 = { fd 90 [2] cf b2 [2] c9 87 [2] e7 87 [2] d8 9b }

  condition:
    any of them
}
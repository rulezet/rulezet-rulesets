rule TTP_XOR_WriteProcessMemory_aae0 {
  strings:
    $key_aae0 = { fd 92 [2] cf b0 [2] c9 85 [2] e7 85 [2] d8 99 }

  condition:
    any of them
}
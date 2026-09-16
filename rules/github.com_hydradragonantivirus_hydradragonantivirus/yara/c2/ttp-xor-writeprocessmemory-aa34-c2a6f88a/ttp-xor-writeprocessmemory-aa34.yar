rule TTP_XOR_WriteProcessMemory_aa34 {
  strings:
    $key_aa34 = { fd 46 [2] cf 64 [2] c9 51 [2] e7 51 [2] d8 4d }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_aa64 {
  strings:
    $key_aa64 = { fd 16 [2] cf 34 [2] c9 01 [2] e7 01 [2] d8 1d }

  condition:
    any of them
}
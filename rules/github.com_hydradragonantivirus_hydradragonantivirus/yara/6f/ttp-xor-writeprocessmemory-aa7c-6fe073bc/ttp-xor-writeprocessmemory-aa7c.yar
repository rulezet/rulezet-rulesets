rule TTP_XOR_WriteProcessMemory_aa7c {
  strings:
    $key_aa7c = { fd 0e [2] cf 2c [2] c9 19 [2] e7 19 [2] d8 05 }

  condition:
    any of them
}
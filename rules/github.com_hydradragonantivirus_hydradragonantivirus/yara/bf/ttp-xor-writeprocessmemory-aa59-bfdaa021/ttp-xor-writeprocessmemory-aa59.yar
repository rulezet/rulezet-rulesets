rule TTP_XOR_WriteProcessMemory_aa59 {
  strings:
    $key_aa59 = { fd 2b [2] cf 09 [2] c9 3c [2] e7 3c [2] d8 20 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_aa0c {
  strings:
    $key_aa0c = { fd 7e [2] cf 5c [2] c9 69 [2] e7 69 [2] d8 75 }

  condition:
    any of them
}
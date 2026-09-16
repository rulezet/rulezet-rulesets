rule TTP_XOR_WriteProcessMemory_aafb {
  strings:
    $key_aafb = { fd 89 [2] cf ab [2] c9 9e [2] e7 9e [2] d8 82 }

  condition:
    any of them
}
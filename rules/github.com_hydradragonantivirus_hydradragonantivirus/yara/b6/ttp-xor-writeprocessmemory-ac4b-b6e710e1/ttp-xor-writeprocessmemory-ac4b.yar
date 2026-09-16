rule TTP_XOR_WriteProcessMemory_ac4b {
  strings:
    $key_ac4b = { fb 39 [2] c9 1b [2] cf 2e [2] e1 2e [2] de 32 }

  condition:
    any of them
}
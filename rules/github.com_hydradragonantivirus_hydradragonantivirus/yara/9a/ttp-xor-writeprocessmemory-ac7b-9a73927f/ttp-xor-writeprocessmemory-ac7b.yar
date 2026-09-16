rule TTP_XOR_WriteProcessMemory_ac7b {
  strings:
    $key_ac7b = { fb 09 [2] c9 2b [2] cf 1e [2] e1 1e [2] de 02 }

  condition:
    any of them
}
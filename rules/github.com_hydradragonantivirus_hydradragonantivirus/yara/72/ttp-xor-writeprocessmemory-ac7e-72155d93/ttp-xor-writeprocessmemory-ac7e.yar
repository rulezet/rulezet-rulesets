rule TTP_XOR_WriteProcessMemory_ac7e {
  strings:
    $key_ac7e = { fb 0c [2] c9 2e [2] cf 1b [2] e1 1b [2] de 07 }

  condition:
    any of them
}
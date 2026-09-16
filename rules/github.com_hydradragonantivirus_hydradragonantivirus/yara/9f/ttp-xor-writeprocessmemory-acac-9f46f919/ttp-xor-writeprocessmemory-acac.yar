rule TTP_XOR_WriteProcessMemory_acac {
  strings:
    $key_acac = { fb de [2] c9 fc [2] cf c9 [2] e1 c9 [2] de d5 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_8eac {
  strings:
    $key_8eac = { d9 de [2] eb fc [2] ed c9 [2] c3 c9 [2] fc d5 }

  condition:
    any of them
}
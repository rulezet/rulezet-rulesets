rule TTP_XOR_WriteProcessMemory_8eec {
  strings:
    $key_8eec = { d9 9e [2] eb bc [2] ed 89 [2] c3 89 [2] fc 95 }

  condition:
    any of them
}
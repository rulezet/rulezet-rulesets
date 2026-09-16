rule TTP_XOR_WriteProcessMemory_8e4c {
  strings:
    $key_8e4c = { d9 3e [2] eb 1c [2] ed 29 [2] c3 29 [2] fc 35 }

  condition:
    any of them
}
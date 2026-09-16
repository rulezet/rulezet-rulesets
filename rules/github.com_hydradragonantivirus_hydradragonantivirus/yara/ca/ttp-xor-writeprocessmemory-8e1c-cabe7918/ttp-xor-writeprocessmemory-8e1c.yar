rule TTP_XOR_WriteProcessMemory_8e1c {
  strings:
    $key_8e1c = { d9 6e [2] eb 4c [2] ed 79 [2] c3 79 [2] fc 65 }

  condition:
    any of them
}
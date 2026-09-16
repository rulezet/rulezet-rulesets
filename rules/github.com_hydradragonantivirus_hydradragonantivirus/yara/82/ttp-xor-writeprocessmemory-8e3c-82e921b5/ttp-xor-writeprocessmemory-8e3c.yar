rule TTP_XOR_WriteProcessMemory_8e3c {
  strings:
    $key_8e3c = { d9 4e [2] eb 6c [2] ed 59 [2] c3 59 [2] fc 45 }

  condition:
    any of them
}
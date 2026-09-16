rule TTP_XOR_WriteProcessMemory_a53c {
  strings:
    $key_a53c = { f2 4e [2] c0 6c [2] c6 59 [2] e8 59 [2] d7 45 }

  condition:
    any of them
}
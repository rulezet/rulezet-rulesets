rule TTP_XOR_WriteProcessMemory_855c {
  strings:
    $key_855c = { d2 2e [2] e0 0c [2] e6 39 [2] c8 39 [2] f7 25 }

  condition:
    any of them
}
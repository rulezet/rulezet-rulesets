rule TTP_XOR_WriteProcessMemory_851e {
  strings:
    $key_851e = { d2 6c [2] e0 4e [2] e6 7b [2] c8 7b [2] f7 67 }

  condition:
    any of them
}
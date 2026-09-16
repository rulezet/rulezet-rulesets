rule TTP_XOR_WriteProcessMemory_8229 {
  strings:
    $key_8229 = { d5 5b [2] e7 79 [2] e1 4c [2] cf 4c [2] f0 50 }

  condition:
    any of them
}
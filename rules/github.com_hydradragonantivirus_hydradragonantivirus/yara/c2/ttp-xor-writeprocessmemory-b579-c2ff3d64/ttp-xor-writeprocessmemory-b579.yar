rule TTP_XOR_WriteProcessMemory_b579 {
  strings:
    $key_b579 = { e2 0b [2] d0 29 [2] d6 1c [2] f8 1c [2] c7 00 }

  condition:
    any of them
}
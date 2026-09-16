rule TTP_XOR_WriteProcessMemory_b539 {
  strings:
    $key_b539 = { e2 4b [2] d0 69 [2] d6 5c [2] f8 5c [2] c7 40 }

  condition:
    any of them
}
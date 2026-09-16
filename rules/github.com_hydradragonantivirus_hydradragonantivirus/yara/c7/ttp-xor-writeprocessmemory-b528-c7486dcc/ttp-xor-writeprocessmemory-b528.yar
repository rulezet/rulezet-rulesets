rule TTP_XOR_WriteProcessMemory_b528 {
  strings:
    $key_b528 = { e2 5a [2] d0 78 [2] d6 4d [2] f8 4d [2] c7 51 }

  condition:
    any of them
}
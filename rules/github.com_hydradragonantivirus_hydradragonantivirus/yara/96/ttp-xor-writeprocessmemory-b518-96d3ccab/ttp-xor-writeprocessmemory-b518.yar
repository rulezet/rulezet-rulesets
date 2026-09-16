rule TTP_XOR_WriteProcessMemory_b518 {
  strings:
    $key_b518 = { e2 6a [2] d0 48 [2] d6 7d [2] f8 7d [2] c7 61 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_b448 {
  strings:
    $key_b448 = { e3 3a [2] d1 18 [2] d7 2d [2] f9 2d [2] c6 31 }

  condition:
    any of them
}
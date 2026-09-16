rule TTP_XOR_WriteProcessMemory_b438 {
  strings:
    $key_b438 = { e3 4a [2] d1 68 [2] d7 5d [2] f9 5d [2] c6 41 }

  condition:
    any of them
}
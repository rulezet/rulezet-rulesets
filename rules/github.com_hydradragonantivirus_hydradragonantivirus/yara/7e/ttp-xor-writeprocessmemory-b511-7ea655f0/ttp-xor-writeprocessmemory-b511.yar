rule TTP_XOR_WriteProcessMemory_b511 {
  strings:
    $key_b511 = { e2 63 [2] d0 41 [2] d6 74 [2] f8 74 [2] c7 68 }

  condition:
    any of them
}
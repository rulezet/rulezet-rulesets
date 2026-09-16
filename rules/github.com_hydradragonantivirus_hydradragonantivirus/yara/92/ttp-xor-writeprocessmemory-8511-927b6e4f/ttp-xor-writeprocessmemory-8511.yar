rule TTP_XOR_WriteProcessMemory_8511 {
  strings:
    $key_8511 = { d2 63 [2] e0 41 [2] e6 74 [2] c8 74 [2] f7 68 }

  condition:
    any of them
}
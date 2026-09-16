rule TTP_XOR_WriteProcessMemory_b4c8 {
  strings:
    $key_b4c8 = { e3 ba [2] d1 98 [2] d7 ad [2] f9 ad [2] c6 b1 }

  condition:
    any of them
}
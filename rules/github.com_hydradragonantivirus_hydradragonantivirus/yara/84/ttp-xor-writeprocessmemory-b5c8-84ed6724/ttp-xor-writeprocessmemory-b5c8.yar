rule TTP_XOR_WriteProcessMemory_b5c8 {
  strings:
    $key_b5c8 = { e2 ba [2] d0 98 [2] d6 ad [2] f8 ad [2] c7 b1 }

  condition:
    any of them
}
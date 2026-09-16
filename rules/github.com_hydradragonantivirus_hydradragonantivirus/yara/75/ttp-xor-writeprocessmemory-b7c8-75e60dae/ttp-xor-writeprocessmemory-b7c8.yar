rule TTP_XOR_WriteProcessMemory_b7c8 {
  strings:
    $key_b7c8 = { e0 ba [2] d2 98 [2] d4 ad [2] fa ad [2] c5 b1 }

  condition:
    any of them
}
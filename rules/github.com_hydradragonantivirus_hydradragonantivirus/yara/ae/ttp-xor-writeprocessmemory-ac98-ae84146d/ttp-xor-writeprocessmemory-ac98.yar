rule TTP_XOR_WriteProcessMemory_ac98 {
  strings:
    $key_ac98 = { fb ea [2] c9 c8 [2] cf fd [2] e1 fd [2] de e1 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_b774 {
  strings:
    $key_b774 = { e0 06 [2] d2 24 [2] d4 11 [2] fa 11 [2] c5 0d }

  condition:
    any of them
}
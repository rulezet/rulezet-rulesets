rule TTP_XOR_WriteProcessMemory_b724 {
  strings:
    $key_b724 = { e0 56 [2] d2 74 [2] d4 41 [2] fa 41 [2] c5 5d }

  condition:
    any of them
}
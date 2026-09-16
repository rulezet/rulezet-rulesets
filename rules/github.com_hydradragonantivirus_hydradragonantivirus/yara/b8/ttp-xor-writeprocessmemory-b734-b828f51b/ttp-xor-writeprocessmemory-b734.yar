rule TTP_XOR_WriteProcessMemory_b734 {
  strings:
    $key_b734 = { e0 46 [2] d2 64 [2] d4 51 [2] fa 51 [2] c5 4d }

  condition:
    any of them
}
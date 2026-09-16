rule TTP_XOR_WriteProcessMemory_a444 {
  strings:
    $key_a444 = { f3 36 [2] c1 14 [2] c7 21 [2] e9 21 [2] d6 3d }

  condition:
    any of them
}
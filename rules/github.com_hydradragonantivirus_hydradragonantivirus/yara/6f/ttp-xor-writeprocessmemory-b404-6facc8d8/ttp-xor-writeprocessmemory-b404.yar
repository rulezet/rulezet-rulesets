rule TTP_XOR_WriteProcessMemory_b404 {
  strings:
    $key_b404 = { e3 76 [2] d1 54 [2] d7 61 [2] f9 61 [2] c6 7d }

  condition:
    any of them
}
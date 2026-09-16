rule TTP_XOR_WriteProcessMemory_b554 {
  strings:
    $key_b554 = { e2 26 [2] d0 04 [2] d6 31 [2] f8 31 [2] c7 2d }

  condition:
    any of them
}
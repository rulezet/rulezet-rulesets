rule TTP_XOR_WriteProcessMemory_a514 {
  strings:
    $key_a514 = { f2 66 [2] c0 44 [2] c6 71 [2] e8 71 [2] d7 6d }

  condition:
    any of them
}
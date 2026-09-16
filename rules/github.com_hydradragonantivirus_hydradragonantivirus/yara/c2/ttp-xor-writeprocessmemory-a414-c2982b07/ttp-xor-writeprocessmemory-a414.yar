rule TTP_XOR_WriteProcessMemory_a414 {
  strings:
    $key_a414 = { f3 66 [2] c1 44 [2] c7 71 [2] e9 71 [2] d6 6d }

  condition:
    any of them
}
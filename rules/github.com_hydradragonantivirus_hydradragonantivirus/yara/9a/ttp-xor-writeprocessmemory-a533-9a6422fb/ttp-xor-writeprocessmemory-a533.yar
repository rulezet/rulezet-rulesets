rule TTP_XOR_WriteProcessMemory_a533 {
  strings:
    $key_a533 = { f2 41 [2] c0 63 [2] c6 56 [2] e8 56 [2] d7 4a }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_a543 {
  strings:
    $key_a543 = { f2 31 [2] c0 13 [2] c6 26 [2] e8 26 [2] d7 3a }

  condition:
    any of them
}
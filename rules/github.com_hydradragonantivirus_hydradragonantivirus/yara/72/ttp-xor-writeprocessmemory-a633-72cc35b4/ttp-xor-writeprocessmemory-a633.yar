rule TTP_XOR_WriteProcessMemory_a633 {
  strings:
    $key_a633 = { f1 41 [2] c3 63 [2] c5 56 [2] eb 56 [2] d4 4a }

  condition:
    any of them
}
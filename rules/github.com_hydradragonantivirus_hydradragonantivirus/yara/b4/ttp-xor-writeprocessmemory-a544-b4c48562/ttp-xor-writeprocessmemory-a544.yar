rule TTP_XOR_WriteProcessMemory_a544 {
  strings:
    $key_a544 = { f2 36 [2] c0 14 [2] c6 21 [2] e8 21 [2] d7 3d }

  condition:
    any of them
}
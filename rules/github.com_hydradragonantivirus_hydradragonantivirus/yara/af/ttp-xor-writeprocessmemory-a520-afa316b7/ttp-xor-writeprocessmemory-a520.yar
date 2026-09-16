rule TTP_XOR_WriteProcessMemory_a520 {
  strings:
    $key_a520 = { f2 52 [2] c0 70 [2] c6 45 [2] e8 45 [2] d7 59 }

  condition:
    any of them
}
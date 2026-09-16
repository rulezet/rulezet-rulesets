rule TTP_XOR_WriteProcessMemory_a004 {
  strings:
    $key_a004 = { f7 76 [2] c5 54 [2] c3 61 [2] ed 61 [2] d2 7d }

  condition:
    any of them
}
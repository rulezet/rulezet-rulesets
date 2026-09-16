rule TTP_XOR_WriteProcessMemory_a062 {
  strings:
    $key_a062 = { f7 10 [2] c5 32 [2] c3 07 [2] ed 07 [2] d2 1b }

  condition:
    any of them
}
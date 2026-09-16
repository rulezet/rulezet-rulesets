rule TTP_XOR_WriteProcessMemory_a407 {
  strings:
    $key_a407 = { f3 75 [2] c1 57 [2] c7 62 [2] e9 62 [2] d6 7e }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_a207 {
  strings:
    $key_a207 = { f5 75 [2] c7 57 [2] c1 62 [2] ef 62 [2] d0 7e }

  condition:
    any of them
}
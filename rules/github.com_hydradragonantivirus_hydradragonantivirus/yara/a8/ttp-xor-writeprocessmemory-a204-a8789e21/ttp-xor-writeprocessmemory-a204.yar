rule TTP_XOR_WriteProcessMemory_a204 {
  strings:
    $key_a204 = { f5 76 [2] c7 54 [2] c1 61 [2] ef 61 [2] d0 7d }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_a274 {
  strings:
    $key_a274 = { f5 06 [2] c7 24 [2] c1 11 [2] ef 11 [2] d0 0d }

  condition:
    any of them
}
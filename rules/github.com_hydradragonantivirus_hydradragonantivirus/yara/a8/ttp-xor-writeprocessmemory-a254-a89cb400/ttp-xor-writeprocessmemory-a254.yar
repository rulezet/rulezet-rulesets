rule TTP_XOR_WriteProcessMemory_a254 {
  strings:
    $key_a254 = { f5 26 [2] c7 04 [2] c1 31 [2] ef 31 [2] d0 2d }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_a276 {
  strings:
    $key_a276 = { f5 04 [2] c7 26 [2] c1 13 [2] ef 13 [2] d0 0f }

  condition:
    any of them
}
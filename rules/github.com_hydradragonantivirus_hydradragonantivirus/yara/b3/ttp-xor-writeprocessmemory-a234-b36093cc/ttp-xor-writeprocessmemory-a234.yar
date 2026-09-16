rule TTP_XOR_WriteProcessMemory_a234 {
  strings:
    $key_a234 = { f5 46 [2] c7 64 [2] c1 51 [2] ef 51 [2] d0 4d }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_abd4 {
  strings:
    $key_abd4 = { fc a6 [2] ce 84 [2] c8 b1 [2] e6 b1 [2] d9 ad }

  condition:
    any of them
}
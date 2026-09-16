rule TTP_XOR_WriteProcessMemory_a249 {
  strings:
    $key_a249 = { f5 3b [2] c7 19 [2] c1 2c [2] ef 2c [2] d0 30 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_a230 {
  strings:
    $key_a230 = { f5 42 [2] c7 60 [2] c1 55 [2] ef 55 [2] d0 49 }

  condition:
    any of them
}
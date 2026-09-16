rule TTP_XOR_WriteProcessMemory_a22c {
  strings:
    $key_a22c = { f5 5e [2] c7 7c [2] c1 49 [2] ef 49 [2] d0 55 }

  condition:
    any of them
}
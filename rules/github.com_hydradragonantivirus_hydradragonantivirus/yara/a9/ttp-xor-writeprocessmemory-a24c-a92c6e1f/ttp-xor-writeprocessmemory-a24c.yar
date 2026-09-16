rule TTP_XOR_WriteProcessMemory_a24c {
  strings:
    $key_a24c = { f5 3e [2] c7 1c [2] c1 29 [2] ef 29 [2] d0 35 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_a269 {
  strings:
    $key_a269 = { f5 1b [2] c7 39 [2] c1 0c [2] ef 0c [2] d0 10 }

  condition:
    any of them
}
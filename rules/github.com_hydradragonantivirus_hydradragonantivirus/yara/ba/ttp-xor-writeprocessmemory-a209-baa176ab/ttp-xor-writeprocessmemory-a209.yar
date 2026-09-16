rule TTP_XOR_WriteProcessMemory_a209 {
  strings:
    $key_a209 = { f5 7b [2] c7 59 [2] c1 6c [2] ef 6c [2] d0 70 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_a219 {
  strings:
    $key_a219 = { f5 6b [2] c7 49 [2] c1 7c [2] ef 7c [2] d0 60 }

  condition:
    any of them
}
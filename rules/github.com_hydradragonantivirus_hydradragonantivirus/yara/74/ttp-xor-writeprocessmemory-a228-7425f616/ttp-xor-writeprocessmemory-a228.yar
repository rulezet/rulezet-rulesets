rule TTP_XOR_WriteProcessMemory_a228 {
  strings:
    $key_a228 = { f5 5a [2] c7 78 [2] c1 4d [2] ef 4d [2] d0 51 }

  condition:
    any of them
}
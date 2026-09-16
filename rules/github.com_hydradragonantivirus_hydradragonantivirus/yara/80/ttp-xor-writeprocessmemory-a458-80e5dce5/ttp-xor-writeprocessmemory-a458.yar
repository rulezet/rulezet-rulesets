rule TTP_XOR_WriteProcessMemory_a458 {
  strings:
    $key_a458 = { f3 2a [2] c1 08 [2] c7 3d [2] e9 3d [2] d6 21 }

  condition:
    any of them
}
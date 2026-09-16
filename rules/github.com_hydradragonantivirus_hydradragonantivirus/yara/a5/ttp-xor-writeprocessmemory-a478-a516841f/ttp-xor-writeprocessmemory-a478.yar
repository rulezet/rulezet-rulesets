rule TTP_XOR_WriteProcessMemory_a478 {
  strings:
    $key_a478 = { f3 0a [2] c1 28 [2] c7 1d [2] e9 1d [2] d6 01 }

  condition:
    any of them
}
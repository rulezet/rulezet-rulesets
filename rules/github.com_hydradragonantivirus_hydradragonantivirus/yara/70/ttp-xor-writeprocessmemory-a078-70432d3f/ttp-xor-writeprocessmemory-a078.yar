rule TTP_XOR_WriteProcessMemory_a078 {
  strings:
    $key_a078 = { f7 0a [2] c5 28 [2] c3 1d [2] ed 1d [2] d2 01 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_a03d {
  strings:
    $key_a03d = { f7 4f [2] c5 6d [2] c3 58 [2] ed 58 [2] d2 44 }

  condition:
    any of them
}
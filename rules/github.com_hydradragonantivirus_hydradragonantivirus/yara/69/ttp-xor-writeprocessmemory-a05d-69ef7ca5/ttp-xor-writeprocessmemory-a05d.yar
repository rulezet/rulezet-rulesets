rule TTP_XOR_WriteProcessMemory_a05d {
  strings:
    $key_a05d = { f7 2f [2] c5 0d [2] c3 38 [2] ed 38 [2] d2 24 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_a04a {
  strings:
    $key_a04a = { f7 38 [2] c5 1a [2] c3 2f [2] ed 2f [2] d2 33 }

  condition:
    any of them
}
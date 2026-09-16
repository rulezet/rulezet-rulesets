rule TTP_XOR_WriteProcessMemory_a45d {
  strings:
    $key_a45d = { f3 2f [2] c1 0d [2] c7 38 [2] e9 38 [2] d6 24 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_a41d {
  strings:
    $key_a41d = { f3 6f [2] c1 4d [2] c7 78 [2] e9 78 [2] d6 64 }

  condition:
    any of them
}
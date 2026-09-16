rule TTP_XOR_WriteProcessMemory_a41f {
  strings:
    $key_a41f = { f3 6d [2] c1 4f [2] c7 7a [2] e9 7a [2] d6 66 }

  condition:
    any of them
}
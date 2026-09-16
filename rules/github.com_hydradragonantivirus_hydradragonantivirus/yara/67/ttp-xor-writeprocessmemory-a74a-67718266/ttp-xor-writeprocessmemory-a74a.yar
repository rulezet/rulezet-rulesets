rule TTP_XOR_WriteProcessMemory_a74a {
  strings:
    $key_a74a = { f0 38 [2] c2 1a [2] c4 2f [2] ea 2f [2] d5 33 }

  condition:
    any of them
}
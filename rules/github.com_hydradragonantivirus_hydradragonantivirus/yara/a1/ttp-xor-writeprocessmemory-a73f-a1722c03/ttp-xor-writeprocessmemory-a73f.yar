rule TTP_XOR_WriteProcessMemory_a73f {
  strings:
    $key_a73f = { f0 4d [2] c2 6f [2] c4 5a [2] ea 5a [2] d5 46 }

  condition:
    any of them
}
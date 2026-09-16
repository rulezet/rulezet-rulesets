rule TTP_XOR_WriteProcessMemory_a7ff {
  strings:
    $key_a7ff = { f0 8d [2] c2 af [2] c4 9a [2] ea 9a [2] d5 86 }

  condition:
    any of them
}
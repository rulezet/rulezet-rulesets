rule TTP_XOR_WriteProcessMemory_a5ff {
  strings:
    $key_a5ff = { f2 8d [2] c0 af [2] c6 9a [2] e8 9a [2] d7 86 }

  condition:
    any of them
}
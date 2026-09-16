rule TTP_XOR_WriteProcessMemory_a6ff {
  strings:
    $key_a6ff = { f1 8d [2] c3 af [2] c5 9a [2] eb 9a [2] d4 86 }

  condition:
    any of them
}
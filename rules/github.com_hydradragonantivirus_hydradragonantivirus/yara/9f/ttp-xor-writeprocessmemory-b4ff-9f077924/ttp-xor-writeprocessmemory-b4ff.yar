rule TTP_XOR_WriteProcessMemory_b4ff {
  strings:
    $key_b4ff = { e3 8d [2] d1 af [2] d7 9a [2] f9 9a [2] c6 86 }

  condition:
    any of them
}
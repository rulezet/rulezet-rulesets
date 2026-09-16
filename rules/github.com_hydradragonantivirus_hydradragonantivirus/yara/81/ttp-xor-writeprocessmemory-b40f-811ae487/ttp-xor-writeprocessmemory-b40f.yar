rule TTP_XOR_WriteProcessMemory_b40f {
  strings:
    $key_b40f = { e3 7d [2] d1 5f [2] d7 6a [2] f9 6a [2] c6 76 }

  condition:
    any of them
}
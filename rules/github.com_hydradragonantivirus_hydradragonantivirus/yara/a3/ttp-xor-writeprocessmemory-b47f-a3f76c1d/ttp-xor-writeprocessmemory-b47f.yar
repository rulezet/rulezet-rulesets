rule TTP_XOR_WriteProcessMemory_b47f {
  strings:
    $key_b47f = { e3 0d [2] d1 2f [2] d7 1a [2] f9 1a [2] c6 06 }

  condition:
    any of them
}
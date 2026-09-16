rule TTP_XOR_WriteProcessMemory_b56f {
  strings:
    $key_b56f = { e2 1d [2] d0 3f [2] d6 0a [2] f8 0a [2] c7 16 }

  condition:
    any of them
}
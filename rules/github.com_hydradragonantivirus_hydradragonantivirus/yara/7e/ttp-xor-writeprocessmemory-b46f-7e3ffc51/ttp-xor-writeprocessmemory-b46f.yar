rule TTP_XOR_WriteProcessMemory_b46f {
  strings:
    $key_b46f = { e3 1d [2] d1 3f [2] d7 0a [2] f9 0a [2] c6 16 }

  condition:
    any of them
}
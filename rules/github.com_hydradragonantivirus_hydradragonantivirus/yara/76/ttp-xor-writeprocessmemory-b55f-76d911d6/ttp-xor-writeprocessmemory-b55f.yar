rule TTP_XOR_WriteProcessMemory_b55f {
  strings:
    $key_b55f = { e2 2d [2] d0 0f [2] d6 3a [2] f8 3a [2] c7 26 }

  condition:
    any of them
}
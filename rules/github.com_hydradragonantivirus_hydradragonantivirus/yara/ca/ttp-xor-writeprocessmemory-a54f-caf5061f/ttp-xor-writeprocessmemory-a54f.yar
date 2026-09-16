rule TTP_XOR_WriteProcessMemory_a54f {
  strings:
    $key_a54f = { f2 3d [2] c0 1f [2] c6 2a [2] e8 2a [2] d7 36 }

  condition:
    any of them
}
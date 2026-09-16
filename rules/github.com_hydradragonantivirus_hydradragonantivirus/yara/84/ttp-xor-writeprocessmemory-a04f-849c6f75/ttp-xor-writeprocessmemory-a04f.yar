rule TTP_XOR_WriteProcessMemory_a04f {
  strings:
    $key_a04f = { f7 3d [2] c5 1f [2] c3 2a [2] ed 2a [2] d2 36 }

  condition:
    any of them
}
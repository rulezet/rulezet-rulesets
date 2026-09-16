rule TTP_XOR_WriteProcessMemory_a05f {
  strings:
    $key_a05f = { f7 2d [2] c5 0f [2] c3 3a [2] ed 3a [2] d2 26 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_a06f {
  strings:
    $key_a06f = { f7 1d [2] c5 3f [2] c3 0a [2] ed 0a [2] d2 16 }

  condition:
    any of them
}
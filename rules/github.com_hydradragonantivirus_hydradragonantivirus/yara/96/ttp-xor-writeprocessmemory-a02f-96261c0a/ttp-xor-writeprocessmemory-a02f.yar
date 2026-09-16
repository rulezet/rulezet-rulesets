rule TTP_XOR_WriteProcessMemory_a02f {
  strings:
    $key_a02f = { f7 5d [2] c5 7f [2] c3 4a [2] ed 4a [2] d2 56 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_a72f {
  strings:
    $key_a72f = { f0 5d [2] c2 7f [2] c4 4a [2] ea 4a [2] d5 56 }

  condition:
    any of them
}
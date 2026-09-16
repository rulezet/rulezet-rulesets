rule TTP_XOR_WriteProcessMemory_a03f {
  strings:
    $key_a03f = { f7 4d [2] c5 6f [2] c3 5a [2] ed 5a [2] d2 46 }

  condition:
    any of them
}
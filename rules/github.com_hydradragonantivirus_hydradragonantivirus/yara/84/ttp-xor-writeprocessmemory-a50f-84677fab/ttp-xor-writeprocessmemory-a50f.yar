rule TTP_XOR_WriteProcessMemory_a50f {
  strings:
    $key_a50f = { f2 7d [2] c0 5f [2] c6 6a [2] e8 6a [2] d7 76 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_a40f {
  strings:
    $key_a40f = { f3 7d [2] c1 5f [2] c7 6a [2] e9 6a [2] d6 76 }

  condition:
    any of them
}
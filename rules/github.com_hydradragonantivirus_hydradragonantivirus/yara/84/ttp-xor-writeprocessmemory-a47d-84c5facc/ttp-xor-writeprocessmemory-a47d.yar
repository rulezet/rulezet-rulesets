rule TTP_XOR_WriteProcessMemory_a47d {
  strings:
    $key_a47d = { f3 0f [2] c1 2d [2] c7 18 [2] e9 18 [2] d6 04 }

  condition:
    any of them
}
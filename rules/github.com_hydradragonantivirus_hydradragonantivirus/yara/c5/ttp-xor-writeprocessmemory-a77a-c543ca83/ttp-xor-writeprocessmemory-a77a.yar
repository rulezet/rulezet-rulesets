rule TTP_XOR_WriteProcessMemory_a77a {
  strings:
    $key_a77a = { f0 08 [2] c2 2a [2] c4 1f [2] ea 1f [2] d5 03 }

  condition:
    any of them
}
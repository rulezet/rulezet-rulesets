rule TTP_XOR_WriteProcessMemory_b37a {
  strings:
    $key_b37a = { e4 08 [2] d6 2a [2] d0 1f [2] fe 1f [2] c1 03 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_b27f {
  strings:
    $key_b27f = { e5 0d [2] d7 2f [2] d1 1a [2] ff 1a [2] c0 06 }

  condition:
    any of them
}
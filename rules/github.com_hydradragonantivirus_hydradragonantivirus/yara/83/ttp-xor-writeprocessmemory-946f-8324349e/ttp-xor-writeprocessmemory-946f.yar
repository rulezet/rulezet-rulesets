rule TTP_XOR_WriteProcessMemory_946f {
  strings:
    $key_946f = { c3 1d [2] f1 3f [2] f7 0a [2] d9 0a [2] e6 16 }

  condition:
    any of them
}
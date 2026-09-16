rule TTP_XOR_WriteProcessMemory_b52f {
  strings:
    $key_b52f = { e2 5d [2] d0 7f [2] d6 4a [2] f8 4a [2] c7 56 }

  condition:
    any of them
}
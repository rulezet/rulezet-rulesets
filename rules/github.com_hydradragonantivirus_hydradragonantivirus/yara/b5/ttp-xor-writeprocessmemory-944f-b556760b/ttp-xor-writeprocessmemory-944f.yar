rule TTP_XOR_WriteProcessMemory_944f {
  strings:
    $key_944f = { c3 3d [2] f1 1f [2] f7 2a [2] d9 2a [2] e6 36 }

  condition:
    any of them
}
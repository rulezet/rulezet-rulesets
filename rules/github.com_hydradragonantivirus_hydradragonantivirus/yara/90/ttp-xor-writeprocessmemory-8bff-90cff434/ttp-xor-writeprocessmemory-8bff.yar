rule TTP_XOR_WriteProcessMemory_8bff {
  strings:
    $key_8bff = { dc 8d [2] ee af [2] e8 9a [2] c6 9a [2] f9 86 }

  condition:
    any of them
}
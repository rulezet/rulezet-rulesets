rule TTP_XOR_WriteProcessMemory_857a {
  strings:
    $key_857a = { d2 08 [2] e0 2a [2] e6 1f [2] c8 1f [2] f7 03 }

  condition:
    any of them
}
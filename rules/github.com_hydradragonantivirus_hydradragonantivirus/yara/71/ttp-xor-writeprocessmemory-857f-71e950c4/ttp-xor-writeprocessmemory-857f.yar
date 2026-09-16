rule TTP_XOR_WriteProcessMemory_857f {
  strings:
    $key_857f = { d2 0d [2] e0 2f [2] e6 1a [2] c8 1a [2] f7 06 }

  condition:
    any of them
}
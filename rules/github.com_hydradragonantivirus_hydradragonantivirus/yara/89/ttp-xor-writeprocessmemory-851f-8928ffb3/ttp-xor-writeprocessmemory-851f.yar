rule TTP_XOR_WriteProcessMemory_851f {
  strings:
    $key_851f = { d2 6d [2] e0 4f [2] e6 7a [2] c8 7a [2] f7 66 }

  condition:
    any of them
}
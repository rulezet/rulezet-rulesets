rule TTP_XOR_WriteProcessMemory_86ca {
  strings:
    $key_86ca = { d1 b8 [2] e3 9a [2] e5 af [2] cb af [2] f4 b3 }

  condition:
    any of them
}
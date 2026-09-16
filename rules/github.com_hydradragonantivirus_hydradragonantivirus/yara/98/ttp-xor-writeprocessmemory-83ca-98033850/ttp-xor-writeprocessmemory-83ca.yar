rule TTP_XOR_WriteProcessMemory_83ca {
  strings:
    $key_83ca = { d4 b8 [2] e6 9a [2] e0 af [2] ce af [2] f1 b3 }

  condition:
    any of them
}
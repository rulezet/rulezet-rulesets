rule TTP_XOR_WriteProcessMemory_87ca {
  strings:
    $key_87ca = { d0 b8 [2] e2 9a [2] e4 af [2] ca af [2] f5 b3 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_94ca {
  strings:
    $key_94ca = { c3 b8 [2] f1 9a [2] f7 af [2] d9 af [2] e6 b3 }

  condition:
    any of them
}
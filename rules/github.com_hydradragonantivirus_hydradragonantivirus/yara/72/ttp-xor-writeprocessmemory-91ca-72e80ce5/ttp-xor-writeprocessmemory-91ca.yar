rule TTP_XOR_WriteProcessMemory_91ca {
  strings:
    $key_91ca = { c6 b8 [2] f4 9a [2] f2 af [2] dc af [2] e3 b3 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_91f8 {
  strings:
    $key_91f8 = { c6 8a [2] f4 a8 [2] f2 9d [2] dc 9d [2] e3 81 }

  condition:
    any of them
}
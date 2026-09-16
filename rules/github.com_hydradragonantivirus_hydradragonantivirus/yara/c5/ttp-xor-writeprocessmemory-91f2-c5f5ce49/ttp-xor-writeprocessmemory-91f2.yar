rule TTP_XOR_WriteProcessMemory_91f2 {
  strings:
    $key_91f2 = { c6 80 [2] f4 a2 [2] f2 97 [2] dc 97 [2] e3 8b }

  condition:
    any of them
}
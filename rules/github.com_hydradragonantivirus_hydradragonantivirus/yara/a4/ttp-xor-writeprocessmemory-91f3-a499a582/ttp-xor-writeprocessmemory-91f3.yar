rule TTP_XOR_WriteProcessMemory_91f3 {
  strings:
    $key_91f3 = { c6 81 [2] f4 a3 [2] f2 96 [2] dc 96 [2] e3 8a }

  condition:
    any of them
}
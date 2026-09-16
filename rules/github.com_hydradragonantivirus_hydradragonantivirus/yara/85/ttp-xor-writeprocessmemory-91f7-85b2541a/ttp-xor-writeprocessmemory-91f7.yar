rule TTP_XOR_WriteProcessMemory_91f7 {
  strings:
    $key_91f7 = { c6 85 [2] f4 a7 [2] f2 92 [2] dc 92 [2] e3 8e }

  condition:
    any of them
}
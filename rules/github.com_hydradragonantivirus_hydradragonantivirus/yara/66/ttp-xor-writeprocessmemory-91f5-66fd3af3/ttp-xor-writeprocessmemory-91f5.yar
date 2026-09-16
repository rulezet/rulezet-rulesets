rule TTP_XOR_WriteProcessMemory_91f5 {
  strings:
    $key_91f5 = { c6 87 [2] f4 a5 [2] f2 90 [2] dc 90 [2] e3 8c }

  condition:
    any of them
}
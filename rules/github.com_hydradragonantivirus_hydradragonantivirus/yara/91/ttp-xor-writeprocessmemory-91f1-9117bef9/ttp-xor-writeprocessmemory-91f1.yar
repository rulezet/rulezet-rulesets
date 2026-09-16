rule TTP_XOR_WriteProcessMemory_91f1 {
  strings:
    $key_91f1 = { c6 83 [2] f4 a1 [2] f2 94 [2] dc 94 [2] e3 88 }

  condition:
    any of them
}
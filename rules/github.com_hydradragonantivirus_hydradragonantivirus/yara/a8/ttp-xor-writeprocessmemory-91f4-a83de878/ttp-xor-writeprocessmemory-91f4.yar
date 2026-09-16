rule TTP_XOR_WriteProcessMemory_91f4 {
  strings:
    $key_91f4 = { c6 86 [2] f4 a4 [2] f2 91 [2] dc 91 [2] e3 8d }

  condition:
    any of them
}
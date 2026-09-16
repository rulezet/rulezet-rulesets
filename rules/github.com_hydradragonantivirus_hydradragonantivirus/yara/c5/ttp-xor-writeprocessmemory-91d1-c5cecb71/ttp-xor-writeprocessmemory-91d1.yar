rule TTP_XOR_WriteProcessMemory_91d1 {
  strings:
    $key_91d1 = { c6 a3 [2] f4 81 [2] f2 b4 [2] dc b4 [2] e3 a8 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_91a8 {
  strings:
    $key_91a8 = { c6 da [2] f4 f8 [2] f2 cd [2] dc cd [2] e3 d1 }

  condition:
    any of them
}
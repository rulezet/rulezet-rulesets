rule TTP_XOR_WriteProcessMemory_85e8 {
  strings:
    $key_85e8 = { d2 9a [2] e0 b8 [2] e6 8d [2] c8 8d [2] f7 91 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_852b {
  strings:
    $key_852b = { d2 59 [2] e0 7b [2] e6 4e [2] c8 4e [2] f7 52 }

  condition:
    any of them
}
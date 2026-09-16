rule TTP_XOR_WriteProcessMemory_3779 {
  strings:
    $key_3779 = { 60 0b [2] 52 29 [2] 54 1c [2] 7a 1c [2] 45 00 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_55f9 {
  strings:
    $key_55f9 = { 02 8b [2] 30 a9 [2] 36 9c [2] 18 9c [2] 27 80 }

  condition:
    any of them
}
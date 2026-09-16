rule TTP_XOR_WriteProcessMemory_35f9 {
  strings:
    $key_35f9 = { 62 8b [2] 50 a9 [2] 56 9c [2] 78 9c [2] 47 80 }

  condition:
    any of them
}
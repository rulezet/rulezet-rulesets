rule TTP_XOR_WriteProcessMemory_4319 {
  strings:
    $key_4319 = { 14 6b [2] 26 49 [2] 20 7c [2] 0e 7c [2] 31 60 }

  condition:
    any of them
}
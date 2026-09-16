rule TTP_XOR_WriteProcessMemory_3369 {
  strings:
    $key_3369 = { 64 1b [2] 56 39 [2] 50 0c [2] 7e 0c [2] 41 10 }

  condition:
    any of them
}
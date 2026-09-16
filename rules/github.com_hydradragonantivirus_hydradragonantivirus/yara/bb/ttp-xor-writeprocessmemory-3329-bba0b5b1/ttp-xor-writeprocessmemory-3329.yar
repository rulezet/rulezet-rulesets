rule TTP_XOR_WriteProcessMemory_3329 {
  strings:
    $key_3329 = { 64 5b [2] 56 79 [2] 50 4c [2] 7e 4c [2] 41 50 }

  condition:
    any of them
}
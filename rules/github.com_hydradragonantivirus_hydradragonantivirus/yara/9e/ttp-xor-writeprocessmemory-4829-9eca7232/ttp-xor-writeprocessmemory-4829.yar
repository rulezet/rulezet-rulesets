rule TTP_XOR_WriteProcessMemory_4829 {
  strings:
    $key_4829 = { 1f 5b [2] 2d 79 [2] 2b 4c [2] 05 4c [2] 3a 50 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_4a29 {
  strings:
    $key_4a29 = { 1d 5b [2] 2f 79 [2] 29 4c [2] 07 4c [2] 38 50 }

  condition:
    any of them
}
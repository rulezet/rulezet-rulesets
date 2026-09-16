rule TTP_XOR_WriteProcessMemory_5a29 {
  strings:
    $key_5a29 = { 0d 5b [2] 3f 79 [2] 39 4c [2] 17 4c [2] 28 50 }

  condition:
    any of them
}
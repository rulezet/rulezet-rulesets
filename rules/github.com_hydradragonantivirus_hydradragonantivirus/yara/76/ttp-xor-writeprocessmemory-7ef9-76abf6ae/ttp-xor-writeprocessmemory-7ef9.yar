rule TTP_XOR_WriteProcessMemory_7ef9 {
  strings:
    $key_7ef9 = { 29 8b [2] 1b a9 [2] 1d 9c [2] 33 9c [2] 0c 80 }

  condition:
    any of them
}
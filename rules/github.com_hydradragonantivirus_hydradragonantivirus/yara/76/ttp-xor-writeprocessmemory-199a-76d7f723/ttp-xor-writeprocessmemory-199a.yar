rule TTP_XOR_WriteProcessMemory_199a {
  strings:
    $key_199a = { 4e e8 [2] 7c ca [2] 7a ff [2] 54 ff [2] 6b e3 }

  condition:
    any of them
}
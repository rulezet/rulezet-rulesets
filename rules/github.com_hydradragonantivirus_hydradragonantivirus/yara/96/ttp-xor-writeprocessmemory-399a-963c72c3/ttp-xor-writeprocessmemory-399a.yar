rule TTP_XOR_WriteProcessMemory_399a {
  strings:
    $key_399a = { 6e e8 [2] 5c ca [2] 5a ff [2] 74 ff [2] 4b e3 }

  condition:
    any of them
}
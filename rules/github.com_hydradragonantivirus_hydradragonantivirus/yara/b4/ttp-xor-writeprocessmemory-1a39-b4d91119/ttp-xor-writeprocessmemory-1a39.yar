rule TTP_XOR_WriteProcessMemory_1a39 {
  strings:
    $key_1a39 = { 4d 4b [2] 7f 69 [2] 79 5c [2] 57 5c [2] 68 40 }

  condition:
    any of them
}
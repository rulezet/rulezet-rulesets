rule TTP_XOR_WriteProcessMemory_1a59 {
  strings:
    $key_1a59 = { 4d 2b [2] 7f 09 [2] 79 3c [2] 57 3c [2] 68 20 }

  condition:
    any of them
}
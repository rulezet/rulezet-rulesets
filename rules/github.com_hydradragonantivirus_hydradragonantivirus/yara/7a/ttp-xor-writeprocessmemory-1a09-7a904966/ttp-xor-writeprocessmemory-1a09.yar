rule TTP_XOR_WriteProcessMemory_1a09 {
  strings:
    $key_1a09 = { 4d 7b [2] 7f 59 [2] 79 6c [2] 57 6c [2] 68 70 }

  condition:
    any of them
}
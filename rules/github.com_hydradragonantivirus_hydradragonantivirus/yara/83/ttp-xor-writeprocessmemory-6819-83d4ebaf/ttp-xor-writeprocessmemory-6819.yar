rule TTP_XOR_WriteProcessMemory_6819 {
  strings:
    $key_6819 = { 3f 6b [2] 0d 49 [2] 0b 7c [2] 25 7c [2] 1a 60 }

  condition:
    any of them
}
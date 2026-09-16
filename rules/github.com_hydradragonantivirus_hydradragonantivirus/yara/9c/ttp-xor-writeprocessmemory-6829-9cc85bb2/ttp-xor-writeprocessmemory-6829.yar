rule TTP_XOR_WriteProcessMemory_6829 {
  strings:
    $key_6829 = { 3f 5b [2] 0d 79 [2] 0b 4c [2] 25 4c [2] 1a 50 }

  condition:
    any of them
}
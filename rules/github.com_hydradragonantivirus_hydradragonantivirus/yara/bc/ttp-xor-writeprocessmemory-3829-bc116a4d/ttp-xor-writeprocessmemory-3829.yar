rule TTP_XOR_WriteProcessMemory_3829 {
  strings:
    $key_3829 = { 6f 5b [2] 5d 79 [2] 5b 4c [2] 75 4c [2] 4a 50 }

  condition:
    any of them
}
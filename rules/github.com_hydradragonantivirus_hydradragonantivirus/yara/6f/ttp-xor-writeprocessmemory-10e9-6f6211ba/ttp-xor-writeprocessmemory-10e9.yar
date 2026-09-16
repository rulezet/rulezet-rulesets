rule TTP_XOR_WriteProcessMemory_10e9 {
  strings:
    $key_10e9 = { 47 9b [2] 75 b9 [2] 73 8c [2] 5d 8c [2] 62 90 }

  condition:
    any of them
}
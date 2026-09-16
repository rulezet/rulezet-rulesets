rule TTP_XOR_WriteProcessMemory_1059 {
  strings:
    $key_1059 = { 47 2b [2] 75 09 [2] 73 3c [2] 5d 3c [2] 62 20 }

  condition:
    any of them
}
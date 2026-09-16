rule TTP_XOR_WriteProcessMemory_4059 {
  strings:
    $key_4059 = { 17 2b [2] 25 09 [2] 23 3c [2] 0d 3c [2] 32 20 }

  condition:
    any of them
}
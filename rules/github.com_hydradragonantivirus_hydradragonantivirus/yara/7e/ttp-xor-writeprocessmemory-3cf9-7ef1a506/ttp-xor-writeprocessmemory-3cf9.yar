rule TTP_XOR_WriteProcessMemory_3cf9 {
  strings:
    $key_3cf9 = { 6b 8b [2] 59 a9 [2] 5f 9c [2] 71 9c [2] 4e 80 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_7809 {
  strings:
    $key_7809 = { 2f 7b [2] 1d 59 [2] 1b 6c [2] 35 6c [2] 0a 70 }

  condition:
    any of them
}
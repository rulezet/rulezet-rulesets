rule TTP_XOR_WriteProcessMemory_3809 {
  strings:
    $key_3809 = { 6f 7b [2] 5d 59 [2] 5b 6c [2] 75 6c [2] 4a 70 }

  condition:
    any of them
}
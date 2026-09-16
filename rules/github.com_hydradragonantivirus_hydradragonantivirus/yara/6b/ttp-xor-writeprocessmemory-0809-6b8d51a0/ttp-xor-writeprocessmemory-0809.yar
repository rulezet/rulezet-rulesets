rule TTP_XOR_WriteProcessMemory_0809 {
  strings:
    $key_0809 = { 5f 7b [2] 6d 59 [2] 6b 6c [2] 45 6c [2] 7a 70 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_0e09 {
  strings:
    $key_0e09 = { 59 7b [2] 6b 59 [2] 6d 6c [2] 43 6c [2] 7c 70 }

  condition:
    any of them
}
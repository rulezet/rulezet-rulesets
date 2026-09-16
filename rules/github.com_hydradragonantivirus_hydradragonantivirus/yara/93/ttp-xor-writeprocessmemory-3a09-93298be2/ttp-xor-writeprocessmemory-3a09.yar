rule TTP_XOR_WriteProcessMemory_3a09 {
  strings:
    $key_3a09 = { 6d 7b [2] 5f 59 [2] 59 6c [2] 77 6c [2] 48 70 }

  condition:
    any of them
}
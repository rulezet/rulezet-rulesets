rule TTP_XOR_WriteProcessMemory_3819 {
  strings:
    $key_3819 = { 6f 6b [2] 5d 49 [2] 5b 7c [2] 75 7c [2] 4a 60 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_0a09 {
  strings:
    $key_0a09 = { 5d 7b [2] 6f 59 [2] 69 6c [2] 47 6c [2] 78 70 }

  condition:
    any of them
}
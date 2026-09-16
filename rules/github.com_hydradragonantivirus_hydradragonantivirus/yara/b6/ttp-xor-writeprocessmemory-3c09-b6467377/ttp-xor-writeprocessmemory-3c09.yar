rule TTP_XOR_WriteProcessMemory_3c09 {
  strings:
    $key_3c09 = { 6b 7b [2] 59 59 [2] 5f 6c [2] 71 6c [2] 4e 70 }

  condition:
    any of them
}
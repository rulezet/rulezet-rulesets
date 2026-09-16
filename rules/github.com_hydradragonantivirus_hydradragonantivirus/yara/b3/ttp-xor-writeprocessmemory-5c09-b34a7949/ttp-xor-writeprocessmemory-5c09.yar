rule TTP_XOR_WriteProcessMemory_5c09 {
  strings:
    $key_5c09 = { 0b 7b [2] 39 59 [2] 3f 6c [2] 11 6c [2] 2e 70 }

  condition:
    any of them
}
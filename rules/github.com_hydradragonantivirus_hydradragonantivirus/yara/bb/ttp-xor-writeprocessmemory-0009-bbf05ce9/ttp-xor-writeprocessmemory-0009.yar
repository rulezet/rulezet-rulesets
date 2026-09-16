rule TTP_XOR_WriteProcessMemory_0009 {
  strings:
    $key_0009 = { 57 7b [2] 65 59 [2] 63 6c [2] 4d 6c [2] 72 70 }

  condition:
    any of them
}
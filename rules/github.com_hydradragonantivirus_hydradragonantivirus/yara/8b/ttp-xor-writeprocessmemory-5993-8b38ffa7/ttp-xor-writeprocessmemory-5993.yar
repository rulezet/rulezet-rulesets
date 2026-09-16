rule TTP_XOR_WriteProcessMemory_5993 {
  strings:
    $key_5993 = { 0e e1 [2] 3c c3 [2] 3a f6 [2] 14 f6 [2] 2b ea }

  condition:
    any of them
}
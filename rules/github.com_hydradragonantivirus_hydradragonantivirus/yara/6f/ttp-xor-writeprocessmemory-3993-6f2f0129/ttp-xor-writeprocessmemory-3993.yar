rule TTP_XOR_WriteProcessMemory_3993 {
  strings:
    $key_3993 = { 6e e1 [2] 5c c3 [2] 5a f6 [2] 74 f6 [2] 4b ea }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_0993 {
  strings:
    $key_0993 = { 5e e1 [2] 6c c3 [2] 6a f6 [2] 44 f6 [2] 7b ea }

  condition:
    any of them
}
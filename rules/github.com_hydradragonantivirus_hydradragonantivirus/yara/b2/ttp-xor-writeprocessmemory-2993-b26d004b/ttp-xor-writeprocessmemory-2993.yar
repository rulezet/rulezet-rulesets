rule TTP_XOR_WriteProcessMemory_2993 {
  strings:
    $key_2993 = { 7e e1 [2] 4c c3 [2] 4a f6 [2] 64 f6 [2] 5b ea }

  condition:
    any of them
}
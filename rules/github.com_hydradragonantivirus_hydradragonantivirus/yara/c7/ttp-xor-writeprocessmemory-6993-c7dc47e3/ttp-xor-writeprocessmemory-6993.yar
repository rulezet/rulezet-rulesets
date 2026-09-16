rule TTP_XOR_WriteProcessMemory_6993 {
  strings:
    $key_6993 = { 3e e1 [2] 0c c3 [2] 0a f6 [2] 24 f6 [2] 1b ea }

  condition:
    any of them
}
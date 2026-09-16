rule TTP_XOR_WriteProcessMemory_e993 {
  strings:
    $key_e993 = { be e1 [2] 8c c3 [2] 8a f6 [2] a4 f6 [2] 9b ea }

  condition:
    any of them
}
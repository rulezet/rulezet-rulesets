rule TTP_XOR_WriteProcessMemory_4245 {
  strings:
    $key_4245 = { 15 37 [2] 27 15 [2] 21 20 [2] 0f 20 [2] 30 3c }

  condition:
    any of them
}
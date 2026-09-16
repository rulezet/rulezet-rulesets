rule TTP_XOR_WriteProcessMemory_7485 {
  strings:
    $key_7485 = { 23 f7 [2] 11 d5 [2] 17 e0 [2] 39 e0 [2] 06 fc }

  condition:
    any of them
}
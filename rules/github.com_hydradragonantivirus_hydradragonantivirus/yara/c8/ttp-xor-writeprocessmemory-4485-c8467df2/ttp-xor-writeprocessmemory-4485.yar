rule TTP_XOR_WriteProcessMemory_4485 {
  strings:
    $key_4485 = { 13 f7 [2] 21 d5 [2] 27 e0 [2] 09 e0 [2] 36 fc }

  condition:
    any of them
}
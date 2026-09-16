rule TTP_XOR_WriteProcessMemory_5394 {
  strings:
    $key_5394 = { 04 e6 [2] 36 c4 [2] 30 f1 [2] 1e f1 [2] 21 ed }

  condition:
    any of them
}
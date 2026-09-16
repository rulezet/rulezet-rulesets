rule TTP_XOR_WriteProcessMemory_2394 {
  strings:
    $key_2394 = { 74 e6 [2] 46 c4 [2] 40 f1 [2] 6e f1 [2] 51 ed }

  condition:
    any of them
}
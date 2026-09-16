rule TTP_XOR_WriteProcessMemory_0394 {
  strings:
    $key_0394 = { 54 e6 [2] 66 c4 [2] 60 f1 [2] 4e f1 [2] 71 ed }

  condition:
    any of them
}
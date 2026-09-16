rule TTP_XOR_WriteProcessMemory_7188 {
  strings:
    $key_7188 = { 26 fa [2] 14 d8 [2] 12 ed [2] 3c ed [2] 03 f1 }

  condition:
    any of them
}
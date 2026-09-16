rule TTP_XOR_WriteProcessMemory_1acc {
  strings:
    $key_1acc = { 4d be [2] 7f 9c [2] 79 a9 [2] 57 a9 [2] 68 b5 }

  condition:
    any of them
}
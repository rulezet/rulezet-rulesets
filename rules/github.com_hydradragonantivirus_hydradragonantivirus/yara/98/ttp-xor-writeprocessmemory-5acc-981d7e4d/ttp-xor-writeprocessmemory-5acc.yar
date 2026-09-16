rule TTP_XOR_WriteProcessMemory_5acc {
  strings:
    $key_5acc = { 0d be [2] 3f 9c [2] 39 a9 [2] 17 a9 [2] 28 b5 }

  condition:
    any of them
}
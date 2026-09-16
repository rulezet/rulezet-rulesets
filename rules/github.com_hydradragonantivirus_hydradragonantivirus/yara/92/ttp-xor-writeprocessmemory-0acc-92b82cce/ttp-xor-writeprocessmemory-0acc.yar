rule TTP_XOR_WriteProcessMemory_0acc {
  strings:
    $key_0acc = { 5d be [2] 6f 9c [2] 69 a9 [2] 47 a9 [2] 78 b5 }

  condition:
    any of them
}
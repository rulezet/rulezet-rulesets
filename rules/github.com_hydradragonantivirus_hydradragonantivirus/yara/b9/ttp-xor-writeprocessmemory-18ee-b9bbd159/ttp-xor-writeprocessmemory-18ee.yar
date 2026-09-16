rule TTP_XOR_WriteProcessMemory_18ee {
  strings:
    $key_18ee = { 4f 9c [2] 7d be [2] 7b 8b [2] 55 8b [2] 6a 97 }

  condition:
    any of them
}
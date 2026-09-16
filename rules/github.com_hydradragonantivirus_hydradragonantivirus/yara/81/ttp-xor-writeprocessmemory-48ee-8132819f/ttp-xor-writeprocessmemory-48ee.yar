rule TTP_XOR_WriteProcessMemory_48ee {
  strings:
    $key_48ee = { 1f 9c [2] 2d be [2] 2b 8b [2] 05 8b [2] 3a 97 }

  condition:
    any of them
}
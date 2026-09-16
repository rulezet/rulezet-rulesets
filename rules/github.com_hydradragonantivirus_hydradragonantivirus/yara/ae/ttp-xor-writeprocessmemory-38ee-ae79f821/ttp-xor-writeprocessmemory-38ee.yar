rule TTP_XOR_WriteProcessMemory_38ee {
  strings:
    $key_38ee = { 6f 9c [2] 5d be [2] 5b 8b [2] 75 8b [2] 4a 97 }

  condition:
    any of them
}
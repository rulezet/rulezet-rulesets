rule TTP_XOR_WriteProcessMemory_08ee {
  strings:
    $key_08ee = { 5f 9c [2] 6d be [2] 6b 8b [2] 45 8b [2] 7a 97 }

  condition:
    any of them
}
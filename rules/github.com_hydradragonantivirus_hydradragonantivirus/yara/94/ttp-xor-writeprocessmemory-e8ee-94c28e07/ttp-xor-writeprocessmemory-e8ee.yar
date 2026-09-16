rule TTP_XOR_WriteProcessMemory_e8ee {
  strings:
    $key_e8ee = { bf 9c [2] 8d be [2] 8b 8b [2] a5 8b [2] 9a 97 }

  condition:
    any of them
}
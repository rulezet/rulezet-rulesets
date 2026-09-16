rule TTP_XOR_WriteProcessMemory_0fee {
  strings:
    $key_0fee = { 58 9c [2] 6a be [2] 6c 8b [2] 42 8b [2] 7d 97 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_7fee {
  strings:
    $key_7fee = { 28 9c [2] 1a be [2] 1c 8b [2] 32 8b [2] 0d 97 }

  condition:
    any of them
}
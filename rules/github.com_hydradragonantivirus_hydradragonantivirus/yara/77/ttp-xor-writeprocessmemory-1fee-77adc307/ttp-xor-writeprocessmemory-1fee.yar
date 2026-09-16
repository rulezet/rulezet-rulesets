rule TTP_XOR_WriteProcessMemory_1fee {
  strings:
    $key_1fee = { 48 9c [2] 7a be [2] 7c 8b [2] 52 8b [2] 6d 97 }

  condition:
    any of them
}
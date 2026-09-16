rule TTP_XOR_WriteProcessMemory_6fee {
  strings:
    $key_6fee = { 38 9c [2] 0a be [2] 0c 8b [2] 22 8b [2] 1d 97 }

  condition:
    any of them
}
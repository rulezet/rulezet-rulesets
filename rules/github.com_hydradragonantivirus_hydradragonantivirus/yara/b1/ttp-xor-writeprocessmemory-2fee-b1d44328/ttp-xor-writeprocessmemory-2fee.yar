rule TTP_XOR_WriteProcessMemory_2fee {
  strings:
    $key_2fee = { 78 9c [2] 4a be [2] 4c 8b [2] 62 8b [2] 5d 97 }

  condition:
    any of them
}
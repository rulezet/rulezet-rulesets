rule TTP_XOR_WriteProcessMemory_5eee {
  strings:
    $key_5eee = { 09 9c [2] 3b be [2] 3d 8b [2] 13 8b [2] 2c 97 }

  condition:
    any of them
}
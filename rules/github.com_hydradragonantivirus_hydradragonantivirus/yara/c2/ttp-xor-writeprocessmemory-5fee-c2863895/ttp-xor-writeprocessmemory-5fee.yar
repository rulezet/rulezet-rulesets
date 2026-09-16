rule TTP_XOR_WriteProcessMemory_5fee {
  strings:
    $key_5fee = { 08 9c [2] 3a be [2] 3c 8b [2] 12 8b [2] 2d 97 }

  condition:
    any of them
}
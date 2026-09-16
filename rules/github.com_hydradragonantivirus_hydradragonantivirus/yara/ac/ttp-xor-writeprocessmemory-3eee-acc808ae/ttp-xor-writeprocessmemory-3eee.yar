rule TTP_XOR_WriteProcessMemory_3eee {
  strings:
    $key_3eee = { 69 9c [2] 5b be [2] 5d 8b [2] 73 8b [2] 4c 97 }

  condition:
    any of them
}
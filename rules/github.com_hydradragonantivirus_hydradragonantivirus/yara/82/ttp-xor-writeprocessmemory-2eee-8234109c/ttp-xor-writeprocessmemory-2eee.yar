rule TTP_XOR_WriteProcessMemory_2eee {
  strings:
    $key_2eee = { 79 9c [2] 4b be [2] 4d 8b [2] 63 8b [2] 5c 97 }

  condition:
    any of them
}
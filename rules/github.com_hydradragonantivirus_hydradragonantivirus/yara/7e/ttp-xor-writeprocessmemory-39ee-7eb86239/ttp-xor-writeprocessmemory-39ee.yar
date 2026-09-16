rule TTP_XOR_WriteProcessMemory_39ee {
  strings:
    $key_39ee = { 6e 9c [2] 5c be [2] 5a 8b [2] 74 8b [2] 4b 97 }

  condition:
    any of them
}
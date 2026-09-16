rule TTP_XOR_WriteProcessMemory_3fee {
  strings:
    $key_3fee = { 68 9c [2] 5a be [2] 5c 8b [2] 72 8b [2] 4d 97 }

  condition:
    any of them
}
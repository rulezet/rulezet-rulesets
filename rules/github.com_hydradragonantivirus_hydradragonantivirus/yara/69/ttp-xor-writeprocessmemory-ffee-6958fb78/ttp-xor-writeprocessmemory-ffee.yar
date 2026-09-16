rule TTP_XOR_WriteProcessMemory_ffee {
  strings:
    $key_ffee = { a8 9c [2] 9a be [2] 9c 8b [2] b2 8b [2] 8d 97 }

  condition:
    any of them
}
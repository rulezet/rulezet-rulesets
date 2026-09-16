rule TTP_XOR_WriteProcessMemory_082e {
  strings:
    $key_082e = { 5f 5c [2] 6d 7e [2] 6b 4b [2] 45 4b [2] 7a 57 }

  condition:
    any of them
}
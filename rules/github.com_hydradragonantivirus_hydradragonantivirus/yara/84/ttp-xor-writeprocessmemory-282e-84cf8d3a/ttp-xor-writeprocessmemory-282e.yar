rule TTP_XOR_WriteProcessMemory_282e {
  strings:
    $key_282e = { 7f 5c [2] 4d 7e [2] 4b 4b [2] 65 4b [2] 5a 57 }

  condition:
    any of them
}
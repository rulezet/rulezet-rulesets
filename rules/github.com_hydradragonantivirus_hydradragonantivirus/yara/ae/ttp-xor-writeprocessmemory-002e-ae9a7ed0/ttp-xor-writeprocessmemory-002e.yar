rule TTP_XOR_WriteProcessMemory_002e {
  strings:
    $key_002e = { 57 5c [2] 65 7e [2] 63 4b [2] 4d 4b [2] 72 57 }

  condition:
    any of them
}
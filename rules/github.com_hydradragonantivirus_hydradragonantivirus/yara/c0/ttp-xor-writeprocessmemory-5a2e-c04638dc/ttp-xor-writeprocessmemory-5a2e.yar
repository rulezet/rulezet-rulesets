rule TTP_XOR_WriteProcessMemory_5a2e {
  strings:
    $key_5a2e = { 0d 5c [2] 3f 7e [2] 39 4b [2] 17 4b [2] 28 57 }

  condition:
    any of them
}
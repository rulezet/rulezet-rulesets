rule TTP_XOR_WriteProcessMemory_0f2e {
  strings:
    $key_0f2e = { 58 5c [2] 6a 7e [2] 6c 4b [2] 42 4b [2] 7d 57 }

  condition:
    any of them
}
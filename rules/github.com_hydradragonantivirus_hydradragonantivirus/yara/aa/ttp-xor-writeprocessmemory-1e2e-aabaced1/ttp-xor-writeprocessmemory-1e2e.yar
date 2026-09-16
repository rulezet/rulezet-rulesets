rule TTP_XOR_WriteProcessMemory_1e2e {
  strings:
    $key_1e2e = { 49 5c [2] 7b 7e [2] 7d 4b [2] 53 4b [2] 6c 57 }

  condition:
    any of them
}
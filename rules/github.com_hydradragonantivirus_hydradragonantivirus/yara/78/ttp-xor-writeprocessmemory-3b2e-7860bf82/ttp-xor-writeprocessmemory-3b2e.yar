rule TTP_XOR_WriteProcessMemory_3b2e {
  strings:
    $key_3b2e = { 6c 5c [2] 5e 7e [2] 58 4b [2] 76 4b [2] 49 57 }

  condition:
    any of them
}
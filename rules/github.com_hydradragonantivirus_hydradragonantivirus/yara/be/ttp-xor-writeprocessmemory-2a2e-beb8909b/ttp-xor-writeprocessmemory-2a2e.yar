rule TTP_XOR_WriteProcessMemory_2a2e {
  strings:
    $key_2a2e = { 7d 5c [2] 4f 7e [2] 49 4b [2] 67 4b [2] 58 57 }

  condition:
    any of them
}
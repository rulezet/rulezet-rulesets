rule TTP_XOR_WriteProcessMemory_2e2b {
  strings:
    $key_2e2b = { 79 59 [2] 4b 7b [2] 4d 4e [2] 63 4e [2] 5c 52 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_2e5b {
  strings:
    $key_2e5b = { 79 29 [2] 4b 0b [2] 4d 3e [2] 63 3e [2] 5c 22 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_2f4b {
  strings:
    $key_2f4b = { 78 39 [2] 4a 1b [2] 4c 2e [2] 62 2e [2] 5d 32 }

  condition:
    any of them
}
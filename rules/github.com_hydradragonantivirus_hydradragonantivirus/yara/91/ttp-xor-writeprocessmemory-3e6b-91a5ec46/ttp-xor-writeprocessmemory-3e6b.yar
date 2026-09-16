rule TTP_XOR_WriteProcessMemory_3e6b {
  strings:
    $key_3e6b = { 69 19 [2] 5b 3b [2] 5d 0e [2] 73 0e [2] 4c 12 }

  condition:
    any of them
}
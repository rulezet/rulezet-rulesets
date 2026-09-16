rule TTP_XOR_WriteProcessMemory_3e3b {
  strings:
    $key_3e3b = { 69 49 [2] 5b 6b [2] 5d 5e [2] 73 5e [2] 4c 42 }

  condition:
    any of them
}
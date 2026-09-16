rule TTP_XOR_WriteProcessMemory_070e {
  strings:
    $key_070e = { 50 7c [2] 62 5e [2] 64 6b [2] 4a 6b [2] 75 77 }

  condition:
    any of them
}
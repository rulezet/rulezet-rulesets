rule TTP_XOR_WriteProcessMemory_7f29 {
  strings:
    $key_7f29 = { 28 5b [2] 1a 79 [2] 1c 4c [2] 32 4c [2] 0d 50 }

  condition:
    any of them
}
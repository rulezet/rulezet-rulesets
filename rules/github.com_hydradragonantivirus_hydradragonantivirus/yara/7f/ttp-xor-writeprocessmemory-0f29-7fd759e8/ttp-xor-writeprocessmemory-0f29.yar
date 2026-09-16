rule TTP_XOR_WriteProcessMemory_0f29 {
  strings:
    $key_0f29 = { 58 5b [2] 6a 79 [2] 6c 4c [2] 42 4c [2] 7d 50 }

  condition:
    any of them
}
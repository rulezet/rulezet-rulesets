rule TTP_XOR_WriteProcessMemory_0f39 {
  strings:
    $key_0f39 = { 58 4b [2] 6a 69 [2] 6c 5c [2] 42 5c [2] 7d 40 }

  condition:
    any of them
}
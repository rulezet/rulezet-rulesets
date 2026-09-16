rule TTP_XOR_WriteProcessMemory_0f79 {
  strings:
    $key_0f79 = { 58 0b [2] 6a 29 [2] 6c 1c [2] 42 1c [2] 7d 00 }

  condition:
    any of them
}
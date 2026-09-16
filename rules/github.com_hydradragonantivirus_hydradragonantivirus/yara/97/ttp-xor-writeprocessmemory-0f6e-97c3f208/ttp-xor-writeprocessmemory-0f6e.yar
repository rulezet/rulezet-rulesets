rule TTP_XOR_WriteProcessMemory_0f6e {
  strings:
    $key_0f6e = { 58 1c [2] 6a 3e [2] 6c 0b [2] 42 0b [2] 7d 17 }

  condition:
    any of them
}
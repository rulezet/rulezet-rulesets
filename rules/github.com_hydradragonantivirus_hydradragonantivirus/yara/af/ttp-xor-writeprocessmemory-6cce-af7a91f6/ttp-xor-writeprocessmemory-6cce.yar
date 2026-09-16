rule TTP_XOR_WriteProcessMemory_6cce {
  strings:
    $key_6cce = { 3b bc [2] 09 9e [2] 0f ab [2] 21 ab [2] 1e b7 }

  condition:
    any of them
}
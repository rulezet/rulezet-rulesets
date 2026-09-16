rule TTP_XOR_WriteProcessMemory_7cce {
  strings:
    $key_7cce = { 2b bc [2] 19 9e [2] 1f ab [2] 31 ab [2] 0e b7 }

  condition:
    any of them
}
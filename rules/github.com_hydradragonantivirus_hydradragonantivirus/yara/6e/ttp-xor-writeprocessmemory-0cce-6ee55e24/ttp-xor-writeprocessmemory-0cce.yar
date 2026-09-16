rule TTP_XOR_WriteProcessMemory_0cce {
  strings:
    $key_0cce = { 5b bc [2] 69 9e [2] 6f ab [2] 41 ab [2] 7e b7 }

  condition:
    any of them
}
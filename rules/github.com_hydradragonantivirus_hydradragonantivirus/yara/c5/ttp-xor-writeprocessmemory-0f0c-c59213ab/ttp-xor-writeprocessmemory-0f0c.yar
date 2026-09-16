rule TTP_XOR_WriteProcessMemory_0f0c {
  strings:
    $key_0f0c = { 58 7e [2] 6a 5c [2] 6c 69 [2] 42 69 [2] 7d 75 }

  condition:
    any of them
}
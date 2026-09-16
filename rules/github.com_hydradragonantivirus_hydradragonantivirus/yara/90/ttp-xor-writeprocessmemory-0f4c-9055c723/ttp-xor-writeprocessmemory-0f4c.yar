rule TTP_XOR_WriteProcessMemory_0f4c {
  strings:
    $key_0f4c = { 58 3e [2] 6a 1c [2] 6c 29 [2] 42 29 [2] 7d 35 }

  condition:
    any of them
}
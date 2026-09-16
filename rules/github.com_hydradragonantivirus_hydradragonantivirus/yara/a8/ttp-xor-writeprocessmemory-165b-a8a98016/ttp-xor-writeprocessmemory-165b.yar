rule TTP_XOR_WriteProcessMemory_165b {
  strings:
    $key_165b = { 41 29 [2] 73 0b [2] 75 3e [2] 5b 3e [2] 64 22 }

  condition:
    any of them
}
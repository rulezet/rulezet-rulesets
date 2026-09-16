rule TTP_XOR_WriteProcessMemory_db5b {
  strings:
    $key_db5b = { 8c 29 [2] be 0b [2] b8 3e [2] 96 3e [2] a9 22 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_1c3b {
  strings:
    $key_1c3b = { 4b 49 [2] 79 6b [2] 7f 5e [2] 51 5e [2] 6e 42 }

  condition:
    any of them
}
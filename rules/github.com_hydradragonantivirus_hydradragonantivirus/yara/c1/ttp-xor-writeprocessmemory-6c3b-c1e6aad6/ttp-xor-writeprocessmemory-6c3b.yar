rule TTP_XOR_WriteProcessMemory_6c3b {
  strings:
    $key_6c3b = { 3b 49 [2] 09 6b [2] 0f 5e [2] 21 5e [2] 1e 42 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_2c3b {
  strings:
    $key_2c3b = { 7b 49 [2] 49 6b [2] 4f 5e [2] 61 5e [2] 5e 42 }

  condition:
    any of them
}
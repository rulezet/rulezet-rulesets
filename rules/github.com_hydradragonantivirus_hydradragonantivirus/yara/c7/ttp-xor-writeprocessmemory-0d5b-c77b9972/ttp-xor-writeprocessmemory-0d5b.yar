rule TTP_XOR_WriteProcessMemory_0d5b {
  strings:
    $key_0d5b = { 5a 29 [2] 68 0b [2] 6e 3e [2] 40 3e [2] 7f 22 }

  condition:
    any of them
}
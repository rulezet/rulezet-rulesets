rule TTP_XOR_WriteProcessMemory_095b {
  strings:
    $key_095b = { 5e 29 [2] 6c 0b [2] 6a 3e [2] 44 3e [2] 7b 22 }

  condition:
    any of them
}
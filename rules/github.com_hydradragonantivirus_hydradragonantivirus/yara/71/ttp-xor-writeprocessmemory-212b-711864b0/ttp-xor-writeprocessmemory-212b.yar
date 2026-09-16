rule TTP_XOR_WriteProcessMemory_212b {
  strings:
    $key_212b = { 76 59 [2] 44 7b [2] 42 4e [2] 6c 4e [2] 53 52 }

  condition:
    any of them
}
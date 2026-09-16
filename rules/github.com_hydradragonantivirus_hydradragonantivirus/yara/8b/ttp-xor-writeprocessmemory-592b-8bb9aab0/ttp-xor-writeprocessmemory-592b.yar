rule TTP_XOR_WriteProcessMemory_592b {
  strings:
    $key_592b = { 0e 59 [2] 3c 7b [2] 3a 4e [2] 14 4e [2] 2b 52 }

  condition:
    any of them
}
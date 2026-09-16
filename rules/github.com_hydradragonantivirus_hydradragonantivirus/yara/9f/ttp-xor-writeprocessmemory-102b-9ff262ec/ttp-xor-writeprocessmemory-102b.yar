rule TTP_XOR_WriteProcessMemory_102b {
  strings:
    $key_102b = { 47 59 [2] 75 7b [2] 73 4e [2] 5d 4e [2] 62 52 }

  condition:
    any of them
}
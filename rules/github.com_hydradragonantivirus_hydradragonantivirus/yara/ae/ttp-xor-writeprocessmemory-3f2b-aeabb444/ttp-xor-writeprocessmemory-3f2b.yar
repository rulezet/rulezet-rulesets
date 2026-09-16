rule TTP_XOR_WriteProcessMemory_3f2b {
  strings:
    $key_3f2b = { 68 59 [2] 5a 7b [2] 5c 4e [2] 72 4e [2] 4d 52 }

  condition:
    any of them
}
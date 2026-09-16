rule TTP_XOR_WriteProcessMemory_5a2b {
  strings:
    $key_5a2b = { 0d 59 [2] 3f 7b [2] 39 4e [2] 17 4e [2] 28 52 }

  condition:
    any of them
}
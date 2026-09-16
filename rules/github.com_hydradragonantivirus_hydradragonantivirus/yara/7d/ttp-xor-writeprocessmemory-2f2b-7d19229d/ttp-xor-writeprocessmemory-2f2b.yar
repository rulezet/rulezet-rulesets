rule TTP_XOR_WriteProcessMemory_2f2b {
  strings:
    $key_2f2b = { 78 59 [2] 4a 7b [2] 4c 4e [2] 62 4e [2] 5d 52 }

  condition:
    any of them
}
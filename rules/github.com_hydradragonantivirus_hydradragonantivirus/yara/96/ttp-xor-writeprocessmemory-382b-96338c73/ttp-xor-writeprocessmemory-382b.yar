rule TTP_XOR_WriteProcessMemory_382b {
  strings:
    $key_382b = { 6f 59 [2] 5d 7b [2] 5b 4e [2] 75 4e [2] 4a 52 }

  condition:
    any of them
}
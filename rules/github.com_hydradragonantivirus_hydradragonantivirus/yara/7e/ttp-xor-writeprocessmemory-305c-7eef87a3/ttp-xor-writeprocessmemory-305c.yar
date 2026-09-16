rule TTP_XOR_WriteProcessMemory_305c {
  strings:
    $key_305c = { 67 2e [2] 55 0c [2] 53 39 [2] 7d 39 [2] 42 25 }

  condition:
    any of them
}
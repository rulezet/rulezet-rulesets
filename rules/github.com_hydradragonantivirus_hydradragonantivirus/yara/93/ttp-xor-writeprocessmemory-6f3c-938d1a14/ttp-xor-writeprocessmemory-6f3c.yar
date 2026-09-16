rule TTP_XOR_WriteProcessMemory_6f3c {
  strings:
    $key_6f3c = { 38 4e [2] 0a 6c [2] 0c 59 [2] 22 59 [2] 1d 45 }

  condition:
    any of them
}
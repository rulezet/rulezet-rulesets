rule TTP_XOR_WriteProcessMemory_1e3c {
  strings:
    $key_1e3c = { 49 4e [2] 7b 6c [2] 7d 59 [2] 53 59 [2] 6c 45 }

  condition:
    any of them
}
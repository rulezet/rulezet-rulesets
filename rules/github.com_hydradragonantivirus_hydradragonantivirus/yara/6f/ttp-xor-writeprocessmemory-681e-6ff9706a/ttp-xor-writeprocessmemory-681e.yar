rule TTP_XOR_WriteProcessMemory_681e {
  strings:
    $key_681e = { 3f 6c [2] 0d 4e [2] 0b 7b [2] 25 7b [2] 1a 67 }

  condition:
    any of them
}
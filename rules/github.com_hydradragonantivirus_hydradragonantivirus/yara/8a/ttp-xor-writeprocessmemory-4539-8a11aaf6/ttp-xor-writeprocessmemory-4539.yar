rule TTP_XOR_WriteProcessMemory_4539 {
  strings:
    $key_4539 = { 12 4b [2] 20 69 [2] 26 5c [2] 08 5c [2] 37 40 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_180c {
  strings:
    $key_180c = { 4f 7e [2] 7d 5c [2] 7b 69 [2] 55 69 [2] 6a 75 }

  condition:
    any of them
}
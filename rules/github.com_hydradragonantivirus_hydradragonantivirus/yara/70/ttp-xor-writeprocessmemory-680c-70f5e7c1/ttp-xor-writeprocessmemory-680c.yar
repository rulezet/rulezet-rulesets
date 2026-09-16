rule TTP_XOR_WriteProcessMemory_680c {
  strings:
    $key_680c = { 3f 7e [2] 0d 5c [2] 0b 69 [2] 25 69 [2] 1a 75 }

  condition:
    any of them
}
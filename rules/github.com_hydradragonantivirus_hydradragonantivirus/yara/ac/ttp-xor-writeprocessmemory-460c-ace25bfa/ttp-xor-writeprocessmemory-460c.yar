rule TTP_XOR_WriteProcessMemory_460c {
  strings:
    $key_460c = { 11 7e [2] 23 5c [2] 25 69 [2] 0b 69 [2] 34 75 }

  condition:
    any of them
}
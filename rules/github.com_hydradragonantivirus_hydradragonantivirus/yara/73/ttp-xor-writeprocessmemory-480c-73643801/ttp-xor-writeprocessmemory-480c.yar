rule TTP_XOR_WriteProcessMemory_480c {
  strings:
    $key_480c = { 1f 7e [2] 2d 5c [2] 2b 69 [2] 05 69 [2] 3a 75 }

  condition:
    any of them
}
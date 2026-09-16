rule TTP_XOR_WriteProcessMemory_382c {
  strings:
    $key_382c = { 6f 5e [2] 5d 7c [2] 5b 49 [2] 75 49 [2] 4a 55 }

  condition:
    any of them
}
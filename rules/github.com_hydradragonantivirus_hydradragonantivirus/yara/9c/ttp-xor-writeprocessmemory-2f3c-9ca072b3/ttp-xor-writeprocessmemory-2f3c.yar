rule TTP_XOR_WriteProcessMemory_2f3c {
  strings:
    $key_2f3c = { 78 4e [2] 4a 6c [2] 4c 59 [2] 62 59 [2] 5d 45 }

  condition:
    any of them
}
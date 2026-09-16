rule TTP_XOR_WriteProcessMemory_fe3c {
  strings:
    $key_fe3c = { a9 4e [2] 9b 6c [2] 9d 59 [2] b3 59 [2] 8c 45 }

  condition:
    any of them
}
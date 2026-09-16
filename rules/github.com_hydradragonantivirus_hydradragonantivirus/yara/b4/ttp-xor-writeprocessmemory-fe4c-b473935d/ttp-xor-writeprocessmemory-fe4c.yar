rule TTP_XOR_WriteProcessMemory_fe4c {
  strings:
    $key_fe4c = { a9 3e [2] 9b 1c [2] 9d 29 [2] b3 29 [2] 8c 35 }

  condition:
    any of them
}
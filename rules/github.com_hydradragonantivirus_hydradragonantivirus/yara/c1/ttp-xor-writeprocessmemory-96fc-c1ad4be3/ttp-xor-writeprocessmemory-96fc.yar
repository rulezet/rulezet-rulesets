rule TTP_XOR_WriteProcessMemory_96fc {
  strings:
    $key_96fc = { c1 8e [2] f3 ac [2] f5 99 [2] db 99 [2] e4 85 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_90fc {
  strings:
    $key_90fc = { c7 8e [2] f5 ac [2] f3 99 [2] dd 99 [2] e2 85 }

  condition:
    any of them
}
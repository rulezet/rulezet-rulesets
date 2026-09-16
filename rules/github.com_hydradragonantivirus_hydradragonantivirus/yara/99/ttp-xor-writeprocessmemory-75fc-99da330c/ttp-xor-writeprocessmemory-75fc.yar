rule TTP_XOR_WriteProcessMemory_75fc {
  strings:
    $key_75fc = { 22 8e [2] 10 ac [2] 16 99 [2] 38 99 [2] 07 85 }

  condition:
    any of them
}
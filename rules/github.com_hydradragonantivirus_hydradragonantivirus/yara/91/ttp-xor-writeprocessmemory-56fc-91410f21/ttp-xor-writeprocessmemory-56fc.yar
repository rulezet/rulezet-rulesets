rule TTP_XOR_WriteProcessMemory_56fc {
  strings:
    $key_56fc = { 01 8e [2] 33 ac [2] 35 99 [2] 1b 99 [2] 24 85 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_62fc {
  strings:
    $key_62fc = { 35 8e [2] 07 ac [2] 01 99 [2] 2f 99 [2] 10 85 }

  condition:
    any of them
}
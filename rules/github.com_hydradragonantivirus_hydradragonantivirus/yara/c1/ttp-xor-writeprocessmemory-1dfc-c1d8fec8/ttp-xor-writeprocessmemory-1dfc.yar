rule TTP_XOR_WriteProcessMemory_1dfc {
  strings:
    $key_1dfc = { 4a 8e [2] 78 ac [2] 7e 99 [2] 50 99 [2] 6f 85 }

  condition:
    any of them
}
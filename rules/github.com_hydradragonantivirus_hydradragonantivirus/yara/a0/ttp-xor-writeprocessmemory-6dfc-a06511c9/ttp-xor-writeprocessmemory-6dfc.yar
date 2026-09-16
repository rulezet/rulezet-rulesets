rule TTP_XOR_WriteProcessMemory_6dfc {
  strings:
    $key_6dfc = { 3a 8e [2] 08 ac [2] 0e 99 [2] 20 99 [2] 1f 85 }

  condition:
    any of them
}
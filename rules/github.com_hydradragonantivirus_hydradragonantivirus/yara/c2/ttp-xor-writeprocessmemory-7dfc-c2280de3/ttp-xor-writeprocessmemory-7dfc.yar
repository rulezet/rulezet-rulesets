rule TTP_XOR_WriteProcessMemory_7dfc {
  strings:
    $key_7dfc = { 2a 8e [2] 18 ac [2] 1e 99 [2] 30 99 [2] 0f 85 }

  condition:
    any of them
}
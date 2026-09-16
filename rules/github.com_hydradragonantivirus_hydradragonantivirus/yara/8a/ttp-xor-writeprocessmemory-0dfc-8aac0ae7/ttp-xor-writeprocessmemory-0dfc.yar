rule TTP_XOR_WriteProcessMemory_0dfc {
  strings:
    $key_0dfc = { 5a 8e [2] 68 ac [2] 6e 99 [2] 40 99 [2] 7f 85 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_6cfc {
  strings:
    $key_6cfc = { 3b 8e [2] 09 ac [2] 0f 99 [2] 21 99 [2] 1e 85 }

  condition:
    any of them
}
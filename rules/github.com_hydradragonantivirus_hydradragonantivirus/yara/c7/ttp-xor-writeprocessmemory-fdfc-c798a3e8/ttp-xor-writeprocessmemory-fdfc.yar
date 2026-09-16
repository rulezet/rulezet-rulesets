rule TTP_XOR_WriteProcessMemory_fdfc {
  strings:
    $key_fdfc = { aa 8e [2] 98 ac [2] 9e 99 [2] b0 99 [2] 8f 85 }

  condition:
    any of them
}
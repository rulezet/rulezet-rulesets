rule TTP_XOR_WriteProcessMemory_d6fc {
  strings:
    $key_d6fc = { 81 8e [2] b3 ac [2] b5 99 [2] 9b 99 [2] a4 85 }

  condition:
    any of them
}
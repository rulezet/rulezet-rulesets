rule TTP_XOR_WriteProcessMemory_c6fc {
  strings:
    $key_c6fc = { 91 8e [2] a3 ac [2] a5 99 [2] 8b 99 [2] b4 85 }

  condition:
    any of them
}
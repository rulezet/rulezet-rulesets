rule TTP_XOR_WriteProcessMemory_d7fc {
  strings:
    $key_d7fc = { 80 8e [2] b2 ac [2] b4 99 [2] 9a 99 [2] a5 85 }

  condition:
    any of them
}
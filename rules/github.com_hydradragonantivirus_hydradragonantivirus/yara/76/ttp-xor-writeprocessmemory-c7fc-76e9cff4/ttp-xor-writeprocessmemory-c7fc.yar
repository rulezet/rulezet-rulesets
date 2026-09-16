rule TTP_XOR_WriteProcessMemory_c7fc {
  strings:
    $key_c7fc = { 90 8e [2] a2 ac [2] a4 99 [2] 8a 99 [2] b5 85 }

  condition:
    any of them
}
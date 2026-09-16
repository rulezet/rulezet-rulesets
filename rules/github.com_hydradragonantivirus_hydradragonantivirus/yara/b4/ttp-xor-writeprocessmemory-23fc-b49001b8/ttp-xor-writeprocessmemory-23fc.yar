rule TTP_XOR_WriteProcessMemory_23fc {
  strings:
    $key_23fc = { 74 8e [2] 46 ac [2] 40 99 [2] 6e 99 [2] 51 85 }

  condition:
    any of them
}
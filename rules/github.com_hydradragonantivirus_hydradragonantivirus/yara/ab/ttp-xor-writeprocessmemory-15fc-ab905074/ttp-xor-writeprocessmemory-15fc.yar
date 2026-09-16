rule TTP_XOR_WriteProcessMemory_15fc {
  strings:
    $key_15fc = { 42 8e [2] 70 ac [2] 76 99 [2] 58 99 [2] 67 85 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_41fc {
  strings:
    $key_41fc = { 16 8e [2] 24 ac [2] 22 99 [2] 0c 99 [2] 33 85 }

  condition:
    any of them
}
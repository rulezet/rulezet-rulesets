rule TTP_XOR_WriteProcessMemory_e5fc {
  strings:
    $key_e5fc = { b2 8e [2] 80 ac [2] 86 99 [2] a8 99 [2] 97 85 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_f5fc {
  strings:
    $key_f5fc = { a2 8e [2] 90 ac [2] 96 99 [2] b8 99 [2] 87 85 }

  condition:
    any of them
}
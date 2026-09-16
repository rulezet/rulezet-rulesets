rule TTP_XOR_WriteProcessMemory_e7fc {
  strings:
    $key_e7fc = { b0 8e [2] 82 ac [2] 84 99 [2] aa 99 [2] 95 85 }

  condition:
    any of them
}
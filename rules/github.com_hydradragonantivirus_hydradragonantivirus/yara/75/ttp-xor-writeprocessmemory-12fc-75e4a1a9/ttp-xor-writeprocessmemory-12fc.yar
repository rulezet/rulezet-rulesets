rule TTP_XOR_WriteProcessMemory_12fc {
  strings:
    $key_12fc = { 45 8e [2] 77 ac [2] 71 99 [2] 5f 99 [2] 60 85 }

  condition:
    any of them
}
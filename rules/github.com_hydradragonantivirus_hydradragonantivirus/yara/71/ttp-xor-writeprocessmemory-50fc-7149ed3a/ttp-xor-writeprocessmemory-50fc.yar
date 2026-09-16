rule TTP_XOR_WriteProcessMemory_50fc {
  strings:
    $key_50fc = { 07 8e [2] 35 ac [2] 33 99 [2] 1d 99 [2] 22 85 }

  condition:
    any of them
}
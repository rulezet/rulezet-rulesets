rule TTP_XOR_WriteProcessMemory_54fc {
  strings:
    $key_54fc = { 03 8e [2] 31 ac [2] 37 99 [2] 19 99 [2] 26 85 }

  condition:
    any of them
}
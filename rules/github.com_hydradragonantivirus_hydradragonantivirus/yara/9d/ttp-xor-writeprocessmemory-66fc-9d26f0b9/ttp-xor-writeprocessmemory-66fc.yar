rule TTP_XOR_WriteProcessMemory_66fc {
  strings:
    $key_66fc = { 31 8e [2] 03 ac [2] 05 99 [2] 2b 99 [2] 14 85 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_42fc {
  strings:
    $key_42fc = { 15 8e [2] 27 ac [2] 21 99 [2] 0f 99 [2] 30 85 }

  condition:
    any of them
}
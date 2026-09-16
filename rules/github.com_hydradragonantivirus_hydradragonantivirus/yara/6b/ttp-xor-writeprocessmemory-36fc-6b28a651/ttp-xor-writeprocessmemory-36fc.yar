rule TTP_XOR_WriteProcessMemory_36fc {
  strings:
    $key_36fc = { 61 8e [2] 53 ac [2] 55 99 [2] 7b 99 [2] 44 85 }

  condition:
    any of them
}
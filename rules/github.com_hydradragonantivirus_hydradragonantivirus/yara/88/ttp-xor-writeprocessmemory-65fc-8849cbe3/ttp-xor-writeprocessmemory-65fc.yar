rule TTP_XOR_WriteProcessMemory_65fc {
  strings:
    $key_65fc = { 32 8e [2] 00 ac [2] 06 99 [2] 28 99 [2] 17 85 }

  condition:
    any of them
}
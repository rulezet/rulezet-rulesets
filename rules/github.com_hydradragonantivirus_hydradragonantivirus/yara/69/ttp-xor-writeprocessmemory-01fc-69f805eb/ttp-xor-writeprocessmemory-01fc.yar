rule TTP_XOR_WriteProcessMemory_01fc {
  strings:
    $key_01fc = { 56 8e [2] 64 ac [2] 62 99 [2] 4c 99 [2] 73 85 }

  condition:
    any of them
}
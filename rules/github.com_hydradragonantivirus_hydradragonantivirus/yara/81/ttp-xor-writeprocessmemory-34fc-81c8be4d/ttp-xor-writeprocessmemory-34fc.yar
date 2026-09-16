rule TTP_XOR_WriteProcessMemory_34fc {
  strings:
    $key_34fc = { 63 8e [2] 51 ac [2] 57 99 [2] 79 99 [2] 46 85 }

  condition:
    any of them
}
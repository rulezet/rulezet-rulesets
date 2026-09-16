rule TTP_XOR_WriteProcessMemory_32fc {
  strings:
    $key_32fc = { 65 8e [2] 57 ac [2] 51 99 [2] 7f 99 [2] 40 85 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_64fc {
  strings:
    $key_64fc = { 33 8e [2] 01 ac [2] 07 99 [2] 29 99 [2] 16 85 }

  condition:
    any of them
}
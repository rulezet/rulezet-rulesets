rule TTP_XOR_WriteProcessMemory_02fc {
  strings:
    $key_02fc = { 55 8e [2] 67 ac [2] 61 99 [2] 4f 99 [2] 70 85 }

  condition:
    any of them
}
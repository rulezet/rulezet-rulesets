rule TTP_XOR_WriteProcessMemory_04fc {
  strings:
    $key_04fc = { 53 8e [2] 61 ac [2] 67 99 [2] 49 99 [2] 76 85 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_27fc {
  strings:
    $key_27fc = { 70 8e [2] 42 ac [2] 44 99 [2] 6a 99 [2] 55 85 }

  condition:
    any of them
}
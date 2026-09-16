rule TTP_XOR_WriteProcessMemory_f3fc {
  strings:
    $key_f3fc = { a4 8e [2] 96 ac [2] 90 99 [2] be 99 [2] 81 85 }

  condition:
    any of them
}
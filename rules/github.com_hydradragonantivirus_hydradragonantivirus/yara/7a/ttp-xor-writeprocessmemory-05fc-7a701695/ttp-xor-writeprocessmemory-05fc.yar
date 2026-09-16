rule TTP_XOR_WriteProcessMemory_05fc {
  strings:
    $key_05fc = { 52 8e [2] 60 ac [2] 66 99 [2] 48 99 [2] 77 85 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_0cfc {
  strings:
    $key_0cfc = { 5b 8e [2] 69 ac [2] 6f 99 [2] 41 99 [2] 7e 85 }

  condition:
    any of them
}
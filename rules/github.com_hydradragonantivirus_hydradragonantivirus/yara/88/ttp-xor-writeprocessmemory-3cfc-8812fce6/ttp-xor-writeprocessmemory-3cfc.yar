rule TTP_XOR_WriteProcessMemory_3cfc {
  strings:
    $key_3cfc = { 6b 8e [2] 59 ac [2] 5f 99 [2] 71 99 [2] 4e 85 }

  condition:
    any of them
}
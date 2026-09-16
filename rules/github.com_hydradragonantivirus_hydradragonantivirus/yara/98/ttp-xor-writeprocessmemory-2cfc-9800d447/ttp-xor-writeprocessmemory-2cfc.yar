rule TTP_XOR_WriteProcessMemory_2cfc {
  strings:
    $key_2cfc = { 7b 8e [2] 49 ac [2] 4f 99 [2] 61 99 [2] 5e 85 }

  condition:
    any of them
}
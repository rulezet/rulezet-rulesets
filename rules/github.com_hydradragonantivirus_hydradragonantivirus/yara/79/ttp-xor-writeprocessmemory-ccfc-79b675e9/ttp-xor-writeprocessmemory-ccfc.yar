rule TTP_XOR_WriteProcessMemory_ccfc {
  strings:
    $key_ccfc = { 9b 8e [2] a9 ac [2] af 99 [2] 81 99 [2] be 85 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_adfc {
  strings:
    $key_adfc = { fa 8e [2] c8 ac [2] ce 99 [2] e0 99 [2] df 85 }

  condition:
    any of them
}
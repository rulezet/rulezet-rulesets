rule TTP_XOR_WriteProcessMemory_bcfc {
  strings:
    $key_bcfc = { eb 8e [2] d9 ac [2] df 99 [2] f1 99 [2] ce 85 }

  condition:
    any of them
}
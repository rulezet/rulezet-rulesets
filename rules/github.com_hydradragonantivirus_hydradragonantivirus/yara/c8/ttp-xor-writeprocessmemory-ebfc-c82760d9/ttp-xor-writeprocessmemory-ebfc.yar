rule TTP_XOR_WriteProcessMemory_ebfc {
  strings:
    $key_ebfc = { bc 8e [2] 8e ac [2] 88 99 [2] a6 99 [2] 99 85 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_2bfc {
  strings:
    $key_2bfc = { 7c 8e [2] 4e ac [2] 48 99 [2] 66 99 [2] 59 85 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_e3c9 {
  strings:
    $key_e3c9 = { b4 bb [2] 86 99 [2] 80 ac [2] ae ac [2] 91 b0 }

  condition:
    any of them
}
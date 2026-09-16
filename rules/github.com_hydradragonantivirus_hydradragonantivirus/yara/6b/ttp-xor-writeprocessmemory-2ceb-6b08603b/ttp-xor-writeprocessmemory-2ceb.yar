rule TTP_XOR_WriteProcessMemory_2ceb {
  strings:
    $key_2ceb = { 7b 99 [2] 49 bb [2] 4f 8e [2] 61 8e [2] 5e 92 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_6ceb {
  strings:
    $key_6ceb = { 3b 99 [2] 09 bb [2] 0f 8e [2] 21 8e [2] 1e 92 }

  condition:
    any of them
}
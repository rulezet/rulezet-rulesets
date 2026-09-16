rule TTP_XOR_WriteProcessMemory_3ceb {
  strings:
    $key_3ceb = { 6b 99 [2] 59 bb [2] 5f 8e [2] 71 8e [2] 4e 92 }

  condition:
    any of them
}
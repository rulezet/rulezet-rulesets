rule TTP_XOR_WriteProcessMemory_adeb {
  strings:
    $key_adeb = { fa 99 [2] c8 bb [2] ce 8e [2] e0 8e [2] df 92 }

  condition:
    any of them
}
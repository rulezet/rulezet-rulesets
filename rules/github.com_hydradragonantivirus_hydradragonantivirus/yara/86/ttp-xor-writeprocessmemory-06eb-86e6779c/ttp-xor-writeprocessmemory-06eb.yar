rule TTP_XOR_WriteProcessMemory_06eb {
  strings:
    $key_06eb = { 51 99 [2] 63 bb [2] 65 8e [2] 4b 8e [2] 74 92 }

  condition:
    any of them
}
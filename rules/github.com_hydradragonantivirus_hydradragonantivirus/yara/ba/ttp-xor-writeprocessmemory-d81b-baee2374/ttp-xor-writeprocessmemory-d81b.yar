rule TTP_XOR_WriteProcessMemory_d81b {
  strings:
    $key_d81b = { 8f 69 [2] bd 4b [2] bb 7e [2] 95 7e [2] aa 62 }

  condition:
    any of them
}
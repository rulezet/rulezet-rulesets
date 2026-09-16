rule TTP_XOR_WriteProcessMemory_136b {
  strings:
    $key_136b = { 44 19 [2] 76 3b [2] 70 0e [2] 5e 0e [2] 61 12 }

  condition:
    any of them
}
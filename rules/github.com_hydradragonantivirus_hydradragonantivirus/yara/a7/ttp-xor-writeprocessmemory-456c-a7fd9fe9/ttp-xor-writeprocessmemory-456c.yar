rule TTP_XOR_WriteProcessMemory_456c {
  strings:
    $key_456c = { 12 1e [2] 20 3c [2] 26 09 [2] 08 09 [2] 37 15 }

  condition:
    any of them
}
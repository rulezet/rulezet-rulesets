rule TTP_XOR_WriteProcessMemory_116c {
  strings:
    $key_116c = { 46 1e [2] 74 3c [2] 72 09 [2] 5c 09 [2] 63 15 }

  condition:
    any of them
}
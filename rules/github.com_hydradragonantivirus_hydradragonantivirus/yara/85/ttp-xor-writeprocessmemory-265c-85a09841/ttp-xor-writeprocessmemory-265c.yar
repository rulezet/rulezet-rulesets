rule TTP_XOR_WriteProcessMemory_265c {
  strings:
    $key_265c = { 71 2e [2] 43 0c [2] 45 39 [2] 6b 39 [2] 54 25 }

  condition:
    any of them
}
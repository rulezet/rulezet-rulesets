rule TTP_XOR_WriteProcessMemory_764c {
  strings:
    $key_764c = { 21 3e [2] 13 1c [2] 15 29 [2] 3b 29 [2] 04 35 }

  condition:
    any of them
}
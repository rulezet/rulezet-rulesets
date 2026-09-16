rule TTP_XOR_WriteProcessMemory_260c {
  strings:
    $key_260c = { 71 7e [2] 43 5c [2] 45 69 [2] 6b 69 [2] 54 75 }

  condition:
    any of them
}
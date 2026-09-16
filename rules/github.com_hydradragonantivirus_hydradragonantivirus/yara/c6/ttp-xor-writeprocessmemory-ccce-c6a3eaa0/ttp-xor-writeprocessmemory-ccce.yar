rule TTP_XOR_WriteProcessMemory_ccce {
  strings:
    $key_ccce = { 9b bc [2] a9 9e [2] af ab [2] 81 ab [2] be b7 }

  condition:
    any of them
}
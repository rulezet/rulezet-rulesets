rule TTP_XOR_WriteProcessMemory_011b {
  strings:
    $key_011b = { 56 69 [2] 64 4b [2] 62 7e [2] 4c 7e [2] 73 62 }

  condition:
    any of them
}
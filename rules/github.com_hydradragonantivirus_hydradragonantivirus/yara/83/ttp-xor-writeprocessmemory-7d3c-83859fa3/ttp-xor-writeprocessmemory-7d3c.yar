rule TTP_XOR_WriteProcessMemory_7d3c {
  strings:
    $key_7d3c = { 2a 4e [2] 18 6c [2] 1e 59 [2] 30 59 [2] 0f 45 }

  condition:
    any of them
}
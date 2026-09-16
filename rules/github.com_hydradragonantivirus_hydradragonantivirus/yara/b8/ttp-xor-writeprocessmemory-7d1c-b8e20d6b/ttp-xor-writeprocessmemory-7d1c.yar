rule TTP_XOR_WriteProcessMemory_7d1c {
  strings:
    $key_7d1c = { 2a 6e [2] 18 4c [2] 1e 79 [2] 30 79 [2] 0f 65 }

  condition:
    any of them
}
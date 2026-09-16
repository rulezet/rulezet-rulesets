rule TTP_XOR_WriteProcessMemory_290b {
  strings:
    $key_290b = { 7e 79 [2] 4c 5b [2] 4a 6e [2] 64 6e [2] 5b 72 }

  condition:
    any of them
}
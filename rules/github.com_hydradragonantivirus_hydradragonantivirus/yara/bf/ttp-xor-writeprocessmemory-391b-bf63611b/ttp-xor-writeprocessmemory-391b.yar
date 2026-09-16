rule TTP_XOR_WriteProcessMemory_391b {
  strings:
    $key_391b = { 6e 69 [2] 5c 4b [2] 5a 7e [2] 74 7e [2] 4b 62 }

  condition:
    any of them
}
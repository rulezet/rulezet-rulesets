rule TTP_XOR_WriteProcessMemory_211b {
  strings:
    $key_211b = { 76 69 [2] 44 4b [2] 42 7e [2] 6c 7e [2] 53 62 }

  condition:
    any of them
}
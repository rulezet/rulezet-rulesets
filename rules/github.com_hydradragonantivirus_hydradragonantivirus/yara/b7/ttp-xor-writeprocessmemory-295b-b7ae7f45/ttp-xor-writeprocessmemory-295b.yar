rule TTP_XOR_WriteProcessMemory_295b {
  strings:
    $key_295b = { 7e 29 [2] 4c 0b [2] 4a 3e [2] 64 3e [2] 5b 22 }

  condition:
    any of them
}
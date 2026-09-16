rule TTP_XOR_WriteProcessMemory_193b {
  strings:
    $key_193b = { 4e 49 [2] 7c 6b [2] 7a 5e [2] 54 5e [2] 6b 42 }

  condition:
    any of them
}
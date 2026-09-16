rule TTP_XOR_WriteProcessMemory_293b {
  strings:
    $key_293b = { 7e 49 [2] 4c 6b [2] 4a 5e [2] 64 5e [2] 5b 42 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_087b {
  strings:
    $key_087b = { 5f 09 [2] 6d 2b [2] 6b 1e [2] 45 1e [2] 7a 02 }

  condition:
    any of them
}
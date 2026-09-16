rule TTP_XOR_WriteProcessMemory_517b {
  strings:
    $key_517b = { 06 09 [2] 34 2b [2] 32 1e [2] 1c 1e [2] 23 02 }

  condition:
    any of them
}
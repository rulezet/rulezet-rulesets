rule TTP_XOR_WriteProcessMemory_624b {
  strings:
    $key_624b = { 35 39 [2] 07 1b [2] 01 2e [2] 2f 2e [2] 10 32 }

  condition:
    any of them
}
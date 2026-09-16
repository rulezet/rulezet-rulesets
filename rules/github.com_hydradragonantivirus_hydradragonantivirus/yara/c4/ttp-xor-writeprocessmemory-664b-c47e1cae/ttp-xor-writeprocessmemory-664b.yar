rule TTP_XOR_WriteProcessMemory_664b {
  strings:
    $key_664b = { 31 39 [2] 03 1b [2] 05 2e [2] 2b 2e [2] 14 32 }

  condition:
    any of them
}
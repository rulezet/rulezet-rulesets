rule TTP_XOR_WriteProcessMemory_347b {
  strings:
    $key_347b = { 63 09 [2] 51 2b [2] 57 1e [2] 79 1e [2] 46 02 }

  condition:
    any of them
}
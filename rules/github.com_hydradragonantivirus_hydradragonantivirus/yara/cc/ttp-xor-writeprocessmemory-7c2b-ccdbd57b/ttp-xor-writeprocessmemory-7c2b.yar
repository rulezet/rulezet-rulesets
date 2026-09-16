rule TTP_XOR_WriteProcessMemory_7c2b {
  strings:
    $key_7c2b = { 2b 59 [2] 19 7b [2] 1f 4e [2] 31 4e [2] 0e 52 }

  condition:
    any of them
}
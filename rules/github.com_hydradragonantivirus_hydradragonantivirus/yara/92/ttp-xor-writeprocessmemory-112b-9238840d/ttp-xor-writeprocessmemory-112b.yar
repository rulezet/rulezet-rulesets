rule TTP_XOR_WriteProcessMemory_112b {
  strings:
    $key_112b = { 46 59 [2] 74 7b [2] 72 4e [2] 5c 4e [2] 63 52 }

  condition:
    any of them
}
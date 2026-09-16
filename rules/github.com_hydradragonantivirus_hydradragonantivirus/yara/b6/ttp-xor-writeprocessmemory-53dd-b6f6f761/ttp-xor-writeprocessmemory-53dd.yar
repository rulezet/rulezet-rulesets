rule TTP_XOR_WriteProcessMemory_53dd {
  strings:
    $key_53dd = { 04 af [2] 36 8d [2] 30 b8 [2] 1e b8 [2] 21 a4 }

  condition:
    any of them
}
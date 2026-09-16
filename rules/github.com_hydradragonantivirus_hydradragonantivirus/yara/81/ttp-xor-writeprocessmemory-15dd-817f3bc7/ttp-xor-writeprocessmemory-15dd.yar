rule TTP_XOR_WriteProcessMemory_15dd {
  strings:
    $key_15dd = { 42 af [2] 70 8d [2] 76 b8 [2] 58 b8 [2] 67 a4 }

  condition:
    any of them
}
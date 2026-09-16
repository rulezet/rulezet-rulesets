rule TTP_XOR_WriteProcessMemory_30dd {
  strings:
    $key_30dd = { 67 af [2] 55 8d [2] 53 b8 [2] 7d b8 [2] 42 a4 }

  condition:
    any of them
}
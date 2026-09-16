rule TTP_XOR_WriteProcessMemory_35dd {
  strings:
    $key_35dd = { 62 af [2] 50 8d [2] 56 b8 [2] 78 b8 [2] 47 a4 }

  condition:
    any of them
}
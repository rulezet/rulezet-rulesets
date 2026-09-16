rule TTP_XOR_WriteProcessMemory_78dd {
  strings:
    $key_78dd = { 2f af [2] 1d 8d [2] 1b b8 [2] 35 b8 [2] 0a a4 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_38dd {
  strings:
    $key_38dd = { 6f af [2] 5d 8d [2] 5b b8 [2] 75 b8 [2] 4a a4 }

  condition:
    any of them
}
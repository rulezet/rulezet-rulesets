rule TTP_XOR_WriteProcessMemory_45dd {
  strings:
    $key_45dd = { 12 af [2] 20 8d [2] 26 b8 [2] 08 b8 [2] 37 a4 }

  condition:
    any of them
}
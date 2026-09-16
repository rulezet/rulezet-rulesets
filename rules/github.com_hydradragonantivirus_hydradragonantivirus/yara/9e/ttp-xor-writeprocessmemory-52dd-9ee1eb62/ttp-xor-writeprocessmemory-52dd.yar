rule TTP_XOR_WriteProcessMemory_52dd {
  strings:
    $key_52dd = { 05 af [2] 37 8d [2] 31 b8 [2] 1f b8 [2] 20 a4 }

  condition:
    any of them
}
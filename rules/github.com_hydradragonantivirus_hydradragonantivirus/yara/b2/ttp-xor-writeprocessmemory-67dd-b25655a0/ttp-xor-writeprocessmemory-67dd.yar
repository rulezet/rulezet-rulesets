rule TTP_XOR_WriteProcessMemory_67dd {
  strings:
    $key_67dd = { 30 af [2] 02 8d [2] 04 b8 [2] 2a b8 [2] 15 a4 }

  condition:
    any of them
}
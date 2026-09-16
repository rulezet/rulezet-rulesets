rule TTP_XOR_WriteProcessMemory_59dd {
  strings:
    $key_59dd = { 0e af [2] 3c 8d [2] 3a b8 [2] 14 b8 [2] 2b a4 }

  condition:
    any of them
}
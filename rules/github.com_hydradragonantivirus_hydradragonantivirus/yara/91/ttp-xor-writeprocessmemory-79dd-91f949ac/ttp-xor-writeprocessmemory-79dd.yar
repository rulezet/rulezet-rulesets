rule TTP_XOR_WriteProcessMemory_79dd {
  strings:
    $key_79dd = { 2e af [2] 1c 8d [2] 1a b8 [2] 34 b8 [2] 0b a4 }

  condition:
    any of them
}
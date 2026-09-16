rule TTP_XOR_WriteProcessMemory_49dd {
  strings:
    $key_49dd = { 1e af [2] 2c 8d [2] 2a b8 [2] 04 b8 [2] 3b a4 }

  condition:
    any of them
}
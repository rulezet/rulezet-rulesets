rule TTP_XOR_WriteProcessMemory_69dd {
  strings:
    $key_69dd = { 3e af [2] 0c 8d [2] 0a b8 [2] 24 b8 [2] 1b a4 }

  condition:
    any of them
}
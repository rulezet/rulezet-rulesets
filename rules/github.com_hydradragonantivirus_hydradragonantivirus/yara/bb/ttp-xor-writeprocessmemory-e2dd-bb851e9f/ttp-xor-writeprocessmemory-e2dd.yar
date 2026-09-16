rule TTP_XOR_WriteProcessMemory_e2dd {
  strings:
    $key_e2dd = { b5 af [2] 87 8d [2] 81 b8 [2] af b8 [2] 90 a4 }

  condition:
    any of them
}
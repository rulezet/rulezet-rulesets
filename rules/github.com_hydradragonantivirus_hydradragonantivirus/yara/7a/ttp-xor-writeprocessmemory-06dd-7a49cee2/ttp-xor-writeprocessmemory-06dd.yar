rule TTP_XOR_WriteProcessMemory_06dd {
  strings:
    $key_06dd = { 51 af [2] 63 8d [2] 65 b8 [2] 4b b8 [2] 74 a4 }

  condition:
    any of them
}
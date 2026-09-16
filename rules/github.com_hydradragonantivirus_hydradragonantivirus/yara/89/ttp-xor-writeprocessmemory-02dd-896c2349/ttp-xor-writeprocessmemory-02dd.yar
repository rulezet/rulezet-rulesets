rule TTP_XOR_WriteProcessMemory_02dd {
  strings:
    $key_02dd = { 55 af [2] 67 8d [2] 61 b8 [2] 4f b8 [2] 70 a4 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_04dd {
  strings:
    $key_04dd = { 53 af [2] 61 8d [2] 67 b8 [2] 49 b8 [2] 76 a4 }

  condition:
    any of them
}
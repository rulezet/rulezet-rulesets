rule TTP_XOR_WriteProcessMemory_7528 {
  strings:
    $key_7528 = { 22 5a [2] 10 78 [2] 16 4d [2] 38 4d [2] 07 51 }

  condition:
    any of them
}
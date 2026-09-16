rule TTP_XOR_WriteProcessMemory_25e8 {
  strings:
    $key_25e8 = { 72 9a [2] 40 b8 [2] 46 8d [2] 68 8d [2] 57 91 }

  condition:
    any of them
}
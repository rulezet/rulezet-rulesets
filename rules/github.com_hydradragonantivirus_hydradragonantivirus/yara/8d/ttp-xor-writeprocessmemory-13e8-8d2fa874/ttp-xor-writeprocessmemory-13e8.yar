rule TTP_XOR_WriteProcessMemory_13e8 {
  strings:
    $key_13e8 = { 44 9a [2] 76 b8 [2] 70 8d [2] 5e 8d [2] 61 91 }

  condition:
    any of them
}
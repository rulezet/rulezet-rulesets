rule TTP_XOR_WriteProcessMemory_17e8 {
  strings:
    $key_17e8 = { 40 9a [2] 72 b8 [2] 74 8d [2] 5a 8d [2] 65 91 }

  condition:
    any of them
}
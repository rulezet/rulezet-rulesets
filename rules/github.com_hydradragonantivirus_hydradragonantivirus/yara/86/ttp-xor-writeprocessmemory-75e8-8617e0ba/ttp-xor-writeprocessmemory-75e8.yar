rule TTP_XOR_WriteProcessMemory_75e8 {
  strings:
    $key_75e8 = { 22 9a [2] 10 b8 [2] 16 8d [2] 38 8d [2] 07 91 }

  condition:
    any of them
}
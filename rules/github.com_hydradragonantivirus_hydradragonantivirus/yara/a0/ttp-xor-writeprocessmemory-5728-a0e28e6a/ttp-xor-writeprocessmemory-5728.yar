rule TTP_XOR_WriteProcessMemory_5728 {
  strings:
    $key_5728 = { 00 5a [2] 32 78 [2] 34 4d [2] 1a 4d [2] 25 51 }

  condition:
    any of them
}
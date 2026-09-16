rule TTP_XOR_WriteProcessMemory_5128 {
  strings:
    $key_5128 = { 06 5a [2] 34 78 [2] 32 4d [2] 1c 4d [2] 23 51 }

  condition:
    any of them
}
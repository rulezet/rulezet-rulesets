rule TTP_XOR_WriteProcessMemory_3438 {
  strings:
    $key_3438 = { 63 4a [2] 51 68 [2] 57 5d [2] 79 5d [2] 46 41 }

  condition:
    any of them
}